// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    internal static bool PlanRemoval(FleetServicePlanNodeRemovalResponse response, Id target, FileServicePlanRemovalRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return CanonicalLimits(outer) && RemovalPlanLimit(outer, request, signedInner: false);
        if (response.Value is not { HasResponse: true } value || value.NodeId is null || !value.NodeId.Equals(target) ||
            value.Response.Length is < 1 or > 1_040_384) return false;
        FileServicePlanRemovalResponse inner;
        try { inner = FileServicePlanRemovalResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) || !ValidRemovalPlanAudit(inner.Audit))
            return false;
        if (inner.Error is { } error) return RemovalPlanError(error, request);
        if (!NodeShapes.IsValid(request) || inner.Value?.Plan is not { } plan ||
            plan.PlanId is null || Validation.RequiredId(plan.PlanId, "plan_id") is not null ||
            !plan.HasDigest || plan.Digest.Length != 32 || plan.ExpiresAt is null ||
            plan.Items.Count is < 1 or > 1001 || !plan.HasTotalBytes || plan.TotalBytes > 67_108_864 ||
            !plan.HasRequiresApproval || !plan.HasQuarantineAvailable || !plan.HasRisk || (int)plan.Risk is < 1 or > 3)
            return false;

        if (request.WorkspacePath is { } workspace)
        {
            if (plan.WorkspacePath is null || !plan.WorkspacePath.Equals(workspace) || plan.AttemptId is not null ||
                plan.Items[0].Path != workspace.Path) return false;
        }
        else if (request.AttemptId is { } attempt)
        {
            if (plan.AttemptId is null || !plan.AttemptId.Equals(attempt) || plan.WorkspacePath is not null ||
                plan.Items[0].Path != string.Empty || plan.Items[0].Kind != FileEntryKind.Directory) return false;
        }
        else return false;

        ulong total = 0;
        var names = new Dictionary<string, FileEntryKind>(StringComparer.Ordinal);
        foreach (var item in plan.Items)
        {
            if (!item.HasPath || !item.HasKind || item.Kind is not (FileEntryKind.File or FileEntryKind.Directory) ||
                !item.HasSizeBytes || !item.HasIdentitySha256 || item.IdentitySha256.Length != 32 || !item.HasOwnerVerified ||
                item.HasSha256 && item.Sha256.Length != 32 || item.Kind == FileEntryKind.Directory && item.SizeBytes != 0 ||
                names.ContainsKey(item.Path)) return false;
            try { _ = WorkspacePath.Components(item.Path, allowRoot: request.AttemptId is not null && item.Path.Length == 0); }
            catch (WorkspacePathException) { return false; }
            if (request.WorkspacePath is { } selected && item.Path != selected.Path &&
                !item.Path.StartsWith(selected.Path + "/", StringComparison.Ordinal)) return false;
            if (names.Count != 0)
            {
                var separator = item.Path.LastIndexOf('/');
                var parent = separator < 0 ? string.Empty : item.Path[..separator];
                if (!names.TryGetValue(parent, out var parentKind) || parentKind != FileEntryKind.Directory) return false;
            }
            names.Add(item.Path, item.Kind);
            if (!item.OwnerVerified && (!plan.RequiresApproval || plan.Risk == RiskClass.Low)) return false;
            if (item.SizeBytes > 67_108_864 - total) return false;
            total += item.SizeBytes;
        }

        return total == plan.TotalBytes;
    }

    private static bool ValidRemovalPlanAudit(FileAuditMetadata? audit)
    {
        if (audit is null || audit.Observations.Count == 0) return true;
        return audit.Observations.Count == 1 && audit.Observations[0] is
        {
            HasKind: true, Kind: FileAuditKind.InputBytes, HasSizeBytes: true,
            HasDigestInputBytes: true, HasSha256: true, Sha256.Length: 32, HasItemCount: false,
        } item && item.SizeBytes is > 0 and <= 67_108_864 && item.DigestInputBytes == item.SizeBytes;
    }

    private static bool AttemptQualificationReason(ArcError error) =>
        error.Details?.State?.Reason is "attempt_references_unverified" or "attempt_tracking_unverified";

    private static bool RemovalPlanError(ArcError error, FileServicePlanRemovalRequest request)
    {
        if (AttemptQualificationReason(error))
            return CommonFileError(error, allowAttemptQualification: true) && NodeShapes.IsValid(request) &&
                request.AttemptId is not null && request.WorkspacePath is null &&
                error.Category == ErrorCategory.State && error.Code == "invalid_state" &&
                error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.Never, RetryAt: null, HasReconciliationOperation: false } &&
                error.Details?.State is { State: "file", Resource: null, Native: null };
        if (!CommonFileError(error) || !RemovalPlanLimit(error, request, signedInner: true)) return false;
        if (error.Category == ErrorCategory.Internal && error.Code == "internal")
            return error.Effect == EffectCertainty.Unknown && error.Retry is { Mode: RetryMode.Never, RetryAt: null };
        if (error.Category == ErrorCategory.State && error.Code == "in_use")
            return error.Effect == EffectCertainty.DidNotHappen && error.Retry is { Mode: RetryMode.AfterTime, RetryAt: not null } &&
                error.Details?.State is not null;
        if (error.Effect != EffectCertainty.DidNotHappen || error.Retry is not { Mode: RetryMode.Never, RetryAt: null })
            return false;
        return (error.Category, error.Code) switch
        {
            (ErrorCategory.Resource, "too_large") => true,
            (ErrorCategory.Validation, "invalid_argument") => error.Details?.State?.Reason.Contains(": ", StringComparison.Ordinal) == true,
            (ErrorCategory.Validation, "path_not_found") or (ErrorCategory.Authorization, "permission_denied") => error.Details?.State is not null,
            (ErrorCategory.State, "not_found") => error.Details?.State?.Resource is not null,
            (ErrorCategory.Conflict, "command_id_reused") => true,
            (ErrorCategory.Conflict, "file_changed") => error.Details?.State is { State: "file" } state &&
                state.Reason is "planned_tree_changed" or "workspace_root_changed" or "file_identity_changed" or
                    "directory_identity_changed" or "directory_changed" or "root_changed" or "parent_identity_changed",
            (ErrorCategory.State, "file_access_denied") => ReadError(error),
            _ => false,
        };
    }

    private static bool RemovalPlanLimit(ArcError error, FileServicePlanRemovalRequest request, bool signedInner)
    {
        if (error.Category != ErrorCategory.Resource || error.Code != "too_large") return true;
        if (error.Details?.Limit is not { HasLimitName: true, Maximum: { } maximum } limit ||
            !Token(limit.LimitName) || !CanonicalDecimal(maximum)) return false;
        bool oversizedPath;
        try { oversizedPath = request.WorkspacePath is { HasPath: true } path && StrictUtf8.GetByteCount(path.Path) > 4096; }
        catch (System.Text.EncoderFallbackException) { return false; }
        return limit.LimitName switch
        {
            "path_bytes" => oversizedPath && maximum.Value == "4096",
            "removal_descendants" => signedInner && maximum.Value == "1000",
            "removal_total_bytes" or "removal_ownership_input_bytes" => signedInner && maximum.Value == "67108864",
            "removal_plan_response_bytes" => signedInner && maximum.Value == "1040384",
            "workspace_root_path_bytes" or "file_write_bytes" or "file_edit_text_bytes" or "file_existing_bytes" or "file_edit_result_bytes" => false,
            _ => maximum.Value switch
            {
                "4096" => oversizedPath,
                "1000" or "67108864" or "1040384" => signedInner,
                _ => false,
            },
        };
    }
}
