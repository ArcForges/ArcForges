// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    internal static bool ExecuteRemoval(FleetServiceExecuteNodeRemovalResponse response, Id target, FileServiceExecuteRemovalRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return CanonicalLimits(outer) &&
            (outer.Category != ErrorCategory.Resource || outer.Code != "too_large" || StatusLimit(FileOperationKind.Removal, outer.Details?.Limit));
        if (response.Value is not { HasResponse: true } value || value.NodeId is null || !value.NodeId.Equals(target) ||
            value.Response.Length is < 1 or > 1_040_384) return false;
        FileServiceExecuteRemovalResponse inner;
        try { inner = FileServiceExecuteRemovalResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) || !StatusAudit(inner.Audit))
            return false;
        if (inner.Error is { } error)
        {
            if (error.Effect == EffectCertainty.Unknown)
                return CommonFileError(error) && error.Category == ErrorCategory.Execution && error.Code == "operation_failed" &&
                    error.Retry is { Mode: RetryMode.Never, RetryAt: null } &&
                    error.Details?.State is { State: "file", Reason: "file_outcome_unknown" };
            return CompletedFileError(FileOperationKind.Removal, error);
        }
        var result = inner.Value?.Result;
        return NodeShapes.IsValid(request) && ValidStatusRemoval(result) && result!.PlanId.Equals(request.PlanId) &&
            (result.Quarantined || request is { HasDeleteWithoutQuarantine: true, DeleteWithoutQuarantine: true });
    }
}
