// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    /// <summary>
    /// Checks a status reply without treating the short status request as the original mutation. The center independently
    /// binds original caller, target and raw digest to its admitted receipt; this client does not possess that receipt.
    /// </summary>
    internal static bool GetFileOperation(FleetServiceGetNodeFileOperationResponse response, Id target, FileServiceGetFileOperationRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return CanonicalLimits(outer) && outer.Code != "too_large";
        if (response.Value is not { HasResponse: true } value || value.NodeId is null || !value.NodeId.Equals(target) ||
            value.Response.Length is < 1 or > 1_040_384) return false;
        FileServiceGetFileOperationResponse inner;
        try { inner = FileServiceGetFileOperationResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) || !StatusAudit(inner.Audit)) return false;
        if (inner.Error is { } error) return StatusError(error);
        var operation = inner.Value?.Operation;
        return NodeShapes.IsValid(request) && request.Meta?.CommandId is null &&
            operation is not null && ValidStatusOperation(operation, request.OperationCommandId);
    }

    private static bool ValidStatusOperation(FileOperation operation, Id? requested)
    {
        if (!NodeShapes.IsValid(operation) || Validation.RequiredId(requested, "operation_command_id") is not null ||
            !operation.CommandId.Equals(requested) || !operation.HasKind || operation.Kind is < FileOperationKind.Write or > FileOperationKind.Removal ||
            !operation.HasState || operation.State is < FileOperationState.Prepared or > FileOperationState.Unknown ||
            !operation.HasRequestSha256 || operation.RequestSha256.Length != 32 || !operation.HasHeld || !operation.HasAcknowledged)
            return false;
        var created = ProtoTime.ToDateTimeOffset(operation.CreatedAt);
        var updated = ProtoTime.ToDateTimeOffset(operation.UpdatedAt);
        if (created is null || updated is null || updated < created) return false;
        if (operation.WorkspacePath is { } path)
        {
            if (Validation.RequiredId(path.WorkspaceId, "workspace_id") is not null || !path.HasPath ||
                path.Path.Length == 0 || path.Path.Contains('\0')) return false;
            try { if (StrictUtf8.GetByteCount(path.Path) > 4096) return false; }
            catch (System.Text.EncoderFallbackException) { return false; }
        }
        else if (operation.Kind != FileOperationKind.Removal ||
            Validation.RequiredId(operation.AttemptId, "attempt_id") is not null)
        {
            return false;
        }

        switch (operation.State)
        {
            case FileOperationState.Prepared:
                return operation.OutcomeCase == FileOperation.OutcomeOneofCase.None && !operation.Acknowledged;
            case FileOperationState.Unknown:
                return operation.Held != operation.Acknowledged && operation.Error is { } unknown &&
                    CommonFileError(unknown) && unknown.Category == ErrorCategory.Execution && unknown.Code == "operation_failed" &&
                    unknown.Effect == EffectCertainty.Unknown && unknown.Retry is { Mode: RetryMode.Never, RetryAt: null } &&
                    unknown.Details?.State is { State: "file", Reason: "file_outcome_unknown" };
            case FileOperationState.Completed:
                if (operation.Held || operation.Acknowledged) return false;
                if (operation.Error is { } failure) return CompletedFileError(operation.Kind, failure);
                if (operation.Kind == FileOperationKind.Removal) return ValidStatusRemoval(operation.Removal);
                var mutation = operation.Mutation;
                return mutation is not null && mutation.CommandId is not null && mutation.CommandId.Equals(operation.CommandId) &&
                    mutation.HasSizeBytes && mutation.SizeBytes <= 4_194_304 && mutation.HasSha256 && mutation.Sha256.Length == 32 &&
                    (operation.Kind == FileOperationKind.Edit
                        ? mutation.HasReplacements && mutation.Replacements is >= 1 and <= 1000
                        : !mutation.HasReplacements);
            default:
                return false;
        }
    }

    private static bool ValidStatusRemoval(FileRemovalResult? result)
    {
        if (result is null || Validation.RequiredId(result.PlanId, "plan_id") is not null || !result.HasQuarantined ||
            !result.HasItemsRemoved || result.ItemsRemoved is < 1 or > 1001 || !result.HasTotalBytes || result.TotalBytes > 67_108_864)
            return false;
        return result.Quarantined
            ? Validation.RequiredId(result.QuarantineId, "quarantine_id") is null && ProtoTime.ToDateTimeOffset(result.PurgeAfter) is not null
            : result.QuarantineId is null && result.PurgeAfter is null;
    }

    private static bool StatusAudit(FileAuditMetadata? audit)
    {
        if (audit is null) return true;
        if (!NodeShapes.IsValid(audit) || audit.Observations.Count > 1) return false;
        return audit.Observations.Count == 0 || audit.Observations[0] is
        {
            Kind: FileAuditKind.OperationMetadata, HasSizeBytes: true, HasDigestInputBytes: true, Sha256.Length: 32,
        } item && item.SizeBytes <= 131_072 && item.DigestInputBytes == item.SizeBytes;
    }

    private static bool CommonFileError(ArcError error)
    {
        if (!NodeShapes.IsValid(error) || Validation.RequiredId(error.CorrelationId, "correlation_id") is not null ||
            !CanonicalLimits(error) || !error.HasCategory || !error.HasCode || !error.HasMessageKey || error.Retry is null ||
            !error.HasEffect || error.CalculateSize() > 4096 ||
            error.MessageKey != "error." + error.Category.ToString().ToLowerInvariant() + "." + error.Code)
            return false;
        if ((error.Retry.Mode == RetryMode.AfterTime) != (error.Retry.RetryAt is not null) ||
            (error.Retry.Mode == RetryMode.Reconcile) != error.Retry.HasReconciliationOperation ||
            error.Retry.RetryAt is { } retryAt && ProtoTime.ToDateTimeOffset(retryAt) is null ||
            error.Retry.HasReconciliationOperation && !Token(error.Retry.ReconciliationOperation))
            return false;
        if (error.Details?.State is { } state && (!Token(state.State) || !Reason(state.Reason) ||
            state.Resource is { } resource && (!Token(resource.Kind) || Validation.RequiredId(resource.Id, "resource.id") is not null)))
            return false;
        return true;
    }

    private static bool StatusError(ArcError error)
    {
        if (!CommonFileError(error) || error.Effect != EffectCertainty.DidNotHappen) return false;
        if (error.Category == ErrorCategory.Internal && error.Code == "internal" ||
            error.Category == ErrorCategory.Resource && error.Code == "overloaded")
            return error.Retry is { Mode: RetryMode.AfterTime, RetryAt: not null };
        if (error.Category == ErrorCategory.Internal && error.Code == "store_corrupt")
            return error.Retry is { Mode: RetryMode.Never, RetryAt: null };
        if (error.Retry is not { Mode: RetryMode.Never, RetryAt: null }) return false;
        return (error.Category, error.Code) switch
        {
            (ErrorCategory.Validation, "invalid_argument") => error.Details?.State?.Reason.Contains(": ", StringComparison.Ordinal) == true,
            (ErrorCategory.State, "not_found") => error.Details?.State?.Resource is not null,
            (ErrorCategory.Authorization, "permission_denied") => error.Details?.State is not null,
            _ => false,
        };
    }

    private static bool CompletedFileError(FileOperationKind kind, ArcError error)
    {
        if (!CommonFileError(error) || error.Effect == EffectCertainty.Unknown) return false;
        var key = (error.Category, error.Code);
        var permitted = key switch
        {
            (ErrorCategory.Validation, "invalid_argument") => true,
            (ErrorCategory.Validation, "path_not_found") => kind is FileOperationKind.Write or FileOperationKind.Edit,
            (ErrorCategory.State, "not_found") or (ErrorCategory.State, "in_use") or (ErrorCategory.State, "expired") or
                (ErrorCategory.Conflict, "digest_mismatch") => kind == FileOperationKind.Removal,
            (ErrorCategory.State, "invalid_state") or (ErrorCategory.State, "file_access_denied") or
                (ErrorCategory.Conflict, "file_changed") or (ErrorCategory.Conflict, "command_id_reused") or
                (ErrorCategory.Resource, "too_large") or (ErrorCategory.Resource, "enforcement_unavailable") or
                (ErrorCategory.Authorization, "permission_denied") or (ErrorCategory.Authorization, "approval_required") or
                (ErrorCategory.Execution, "operation_failed") or (ErrorCategory.Internal, "internal") or
                (ErrorCategory.Internal, "store_corrupt") or (ErrorCategory.Resource, "overloaded") => true,
            (ErrorCategory.Conflict, "occurrence_mismatch") => kind == FileOperationKind.Edit,
            _ => false,
        };
        if (!permitted) return false;
        if (key == (ErrorCategory.Resource, "too_large")) return error.Effect == EffectCertainty.DidNotHappen &&
            error.Retry is { Mode: RetryMode.Never, RetryAt: null } && StatusLimit(kind, error.Details?.Limit);
        if (key == (ErrorCategory.Execution, "operation_failed"))
            return error.Effect == EffectCertainty.Happened &&
                error.Retry is { Mode: RetryMode.Never or RetryMode.SameCommand, RetryAt: null } &&
                error.Details?.State is { State: "file" };
        if (key == (ErrorCategory.Internal, "internal"))
            return error.Retry is { Mode: RetryMode.AfterTime, RetryAt: not null };
        if (key is (ErrorCategory.State, "in_use") or (ErrorCategory.Resource, "overloaded"))
            return error.Effect == EffectCertainty.DidNotHappen && error.Retry is { Mode: RetryMode.AfterTime, RetryAt: not null } &&
                (key != (ErrorCategory.State, "in_use") || error.Details?.State is not null);
        if (key == (ErrorCategory.Authorization, "approval_required"))
            return error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.Reconcile, ReconciliationOperation: "arcforges.node.v1.ApprovalService/GetApproval" } &&
                error.Details?.State?.Resource is { Kind: "approval" };
        if (error.Effect != EffectCertainty.DidNotHappen || error.Retry is not { Mode: RetryMode.Never, RetryAt: null }) return false;
        var state = error.Details?.State;
        return key switch
        {
            (ErrorCategory.Validation, "invalid_argument") => state?.Reason.Contains(": ", StringComparison.Ordinal) == true,
            (ErrorCategory.Validation, "path_not_found") or (ErrorCategory.State, "invalid_state") or
                (ErrorCategory.Resource, "enforcement_unavailable") or (ErrorCategory.Authorization, "permission_denied") => state is not null,
            (ErrorCategory.State, "not_found") => state?.Resource is not null,
            (ErrorCategory.Conflict, "occurrence_mismatch") => state is { State: "file", Reason: "occurrence_mismatch" },
            (ErrorCategory.Conflict, "file_changed") => state is { State: "file" } && (state.Reason switch
            {
                "hash_mismatch" => kind is FileOperationKind.Write or FileOperationKind.Edit,
                "expected_absent_conflict" => kind == FileOperationKind.Write,
                "planned_tree_changed" => kind == FileOperationKind.Removal,
                "workspace_root_changed" or "workspace_path_conflict" or "workspace_identity_conflict" or
                "workspace_registration_changed" or "legacy_snapshot_changed" or "file_identity_changed" or
                "directory_identity_changed" or "directory_changed" or "root_changed" or "file_changed_while_reading" or
                "parent_identity_changed" => true,
                _ => false,
            }),
            (ErrorCategory.State, "file_access_denied") => state is { State: "file" } &&
                state.Reason is "file_access_denied" or "file_hard_link" or "file_metadata_unavailable" or "path_link_or_special" or
                    "mount_crossing" or "canonical_path_unavailable" or "case_semantics_unavailable" or "directory_entry_invalid" or
                    "directory_enumeration_failed" or "directory_enumeration_unavailable" or
                    "identity_filesystem_unavailable" or "identity_handle_unavailable" or "identity_unavailable" or
                    "identity_unavailable_or_reparse" or "procfs_unavailable" or "root_not_supported",
            _ => true,
        };
    }

    private static bool StatusLimit(FileOperationKind kind, LimitFailure? limit)
    {
        if (limit is not { HasLimitName: true, Maximum: { } maximum } || !Token(limit.LimitName) || !CanonicalDecimal(maximum))
            return false;
        var canonical = limit.LimitName switch
        {
            "path_bytes" => "4096",
            "workspace_root_path_bytes" => "4096",
            "file_write_bytes" => "196608",
            "file_edit_text_bytes" => "65536",
            "file_existing_bytes" => "4194304",
            "file_edit_result_bytes" => "4194304",
            "removal_descendants" => "1000",
            "removal_total_bytes" => "67108864",
            "removal_ownership_input_bytes" => "67108864",
            "removal_plan_response_bytes" => "1040384",
            _ => null,
        };
        bool Possible(string name) => name switch
        {
            // A valid persisted workspace target is already known to fit; it cannot prove a path-size refusal.
            "path_bytes" or "workspace_root_path_bytes" => false,
            "file_write_bytes" => kind == FileOperationKind.Write,
            "file_edit_text_bytes" or "file_edit_result_bytes" => kind == FileOperationKind.Edit,
            "file_existing_bytes" => kind is FileOperationKind.Write or FileOperationKind.Edit,
            "removal_descendants" or "removal_total_bytes" => kind == FileOperationKind.Removal,
            _ => false,
        };
        if (canonical is not null) return maximum.Value == canonical && Possible(limit.LimitName);
        return maximum.Value switch
        {
            "196608" => Possible("file_write_bytes"),
            "65536" => Possible("file_edit_text_bytes"),
            "4194304" => Possible("file_existing_bytes") || Possible("file_edit_result_bytes"),
            "1000" => Possible("removal_descendants"),
            "67108864" => Possible("removal_total_bytes"),
            _ => false,
        };
    }
}
