// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    // The original request is available here, unlike a later operation-status lookup.
    internal static bool Write(FleetServiceWriteNodeFileResponse response, Id target, FileServiceWriteFileRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return CanonicalLimits(outer) && MutationLimit(outer, request, null);
        if (response.Value is not { HasResponse: true } value || value.NodeId is null || !value.NodeId.Equals(target) ||
            value.Response.Length is < 1 or > 1_040_384) return false;
        FileServiceWriteFileResponse inner;
        try { inner = FileServiceWriteFileResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) ||
            !MutationAudit(inner.Audit, inner.Value?.Result, inner.Error is null)) return false;
        if (inner.Error is { } error) return MutationError(FileOperationKind.Write, error, request, null);
        var result = inner.Value?.Result;
        return NodeShapes.IsValid(request) && request.HasData &&
            ValidMutation(result, request.Meta?.CommandId, edit: false) &&
            result!.SizeBytes == (ulong)request.Data.Length &&
            CryptographicOperations.FixedTimeEquals(result.Sha256.Span, SHA256.HashData(request.Data.Span));
    }

    internal static bool Edit(FleetServiceEditNodeFileResponse response, Id target, FileServiceEditFileRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return CanonicalLimits(outer) && MutationLimit(outer, null, request);
        if (response.Value is not { HasResponse: true } value || value.NodeId is null || !value.NodeId.Equals(target) ||
            value.Response.Length is < 1 or > 1_040_384) return false;
        FileServiceEditFileResponse inner;
        try { inner = FileServiceEditFileResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) ||
            !MutationAudit(inner.Audit, inner.Value?.Result, inner.Error is null)) return false;
        if (inner.Error is { } error) return MutationError(FileOperationKind.Edit, error, null, request);
        var result = inner.Value?.Result;
        return NodeShapes.IsValid(request) && request.HasExpectedOccurrences &&
            ValidMutation(result, request.Meta?.CommandId, edit: true) && result!.Replacements == request.ExpectedOccurrences;
    }

    private static bool ValidMutation(FileMutationResult? result, Id? command, bool edit) =>
        result is not null && Validation.RequiredId(command, "command_id") is null && result.CommandId is not null &&
        result.CommandId.Equals(command) && result.HasSizeBytes && result.SizeBytes <= 4_194_304 &&
        result.HasSha256 && result.Sha256.Length == 32 &&
        (edit ? result.HasReplacements && result.Replacements is >= 1 and <= 1000 : !result.HasReplacements);

    private static bool MutationAudit(FileAuditMetadata? audit, FileMutationResult? result, bool success)
    {
        if (audit is null) return !success;
        if (!NodeShapes.IsValid(audit) || audit.Observations.Count > 2) return false;
        var input = false;
        var written = false;
        foreach (var item in audit.Observations)
        {
            if (!item.HasKind || !item.HasSizeBytes || !item.HasDigestInputBytes || !item.HasSha256 ||
                item.Sha256.Length != 32 || item.SizeBytes > 4_194_304 || item.DigestInputBytes != item.SizeBytes ||
                item.HasItemCount && item.ItemCount > 10_001) return false;
            if (item.Kind == FileAuditKind.InputBytes && !input) input = true;
            else if (item.Kind == FileAuditKind.WrittenBytes && !written)
            {
                written = true;
                if (success && (result is null || item.SizeBytes != result.SizeBytes ||
                    !CryptographicOperations.FixedTimeEquals(item.Sha256.Span, result.Sha256.Span))) return false;
            }
            else return false;
        }
        return !success || written;
    }

    private static bool MutationError(FileOperationKind kind, ArcError error,
        FileServiceWriteFileRequest? write, FileServiceEditFileRequest? edit)
    {
        if (!CommonFileError(error) || !MutationLimit(error, write, edit)) return false;
        if (error.Category == ErrorCategory.Resource && error.Code == "too_large")
            return error.Effect == EffectCertainty.DidNotHappen && error.Retry is { Mode: RetryMode.Never, RetryAt: null };
        if (error.Effect == EffectCertainty.Unknown)
            return error.Category == ErrorCategory.Execution && error.Code == "operation_failed" &&
                error.Retry is { Mode: RetryMode.Never, RetryAt: null } &&
                error.Details?.State is { State: "file", Reason: "file_outcome_unknown" };
        if (!CompletedFileError(kind, error)) return false;
        if (error.Category == ErrorCategory.Conflict && error.Code == "file_changed")
        {
            return error.Details?.State?.Reason switch
            {
                "hash_mismatch" => write is not null ? write.HasExpectedSha256 : edit?.HasExpectedSha256 == true,
                "expected_absent_conflict" => write is { HasExpectedAbsent: true, ExpectedAbsent: true },
                _ => true,
            };
        }
        return true;
    }

    // Limit names are open in the published contract. Canonical names retain their
    // fixed meaning; an opaque name is accepted only when some real bound remains possible.
    private static bool MutationLimit(ArcError error, FileServiceWriteFileRequest? write, FileServiceEditFileRequest? edit)
    {
        if (error.Category != ErrorCategory.Resource || error.Code != "too_large") return true;
        var limit = error.Details?.Limit;
        if (limit is not { HasLimitName: true, Maximum: { } maximum } ||
            !Token(limit.LimitName) || !CanonicalDecimal(maximum)) return false;
        bool possiblePath;
        bool possibleEditText;
        bool possibleEditResult;
        try
        {
            possiblePath = StrictUtf8.GetByteCount(write?.Path?.Path ?? edit?.Path?.Path ?? "") > 4096;
            possibleEditText = edit is not null &&
                (StrictUtf8.GetByteCount(edit.OldText) > 65_536 || StrictUtf8.GetByteCount(edit.NewText) > 65_536);
            possibleEditResult = edit is { HasOldText: true, HasNewText: true } &&
                StrictUtf8.GetByteCount(edit.NewText) > StrictUtf8.GetByteCount(edit.OldText);
        }
        catch (System.Text.EncoderFallbackException) { return false; }
        bool possibleWrite = write is not null && write.Data.Length > 196_608;
        bool possibleExisting = write is not null || edit is not null;
        return limit.LimitName switch
        {
            "path_bytes" => maximum.Value == "4096" && possiblePath,
            "workspace_root_path_bytes" or "removal_descendants" or "removal_total_bytes" or "removal_ownership_input_bytes" or "removal_plan_response_bytes" => false,
            "file_write_bytes" => maximum.Value == "196608" && possibleWrite,
            "file_edit_text_bytes" => maximum.Value == "65536" && possibleEditText,
            "file_existing_bytes" => maximum.Value == "4194304" && possibleExisting,
            "file_edit_result_bytes" => maximum.Value == "4194304" && possibleEditResult,
            _ => maximum.Value switch
            {
                "4096" => possiblePath,
                "196608" => possibleWrite,
                "65536" => possibleEditText,
                "4194304" => possibleExisting || possibleEditResult,
                _ => false,
            },
        };
    }
}
