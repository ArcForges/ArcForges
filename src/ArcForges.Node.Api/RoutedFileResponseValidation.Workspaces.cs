// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    internal static bool RegisterWorkspace(FleetServiceRegisterNodeWorkspaceResponse response, Id target, WorkspaceServiceRegisterWorkspaceRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return WorkspaceLimit(outer, request);
        if (response.Value is not { HasResponse: true } value || !WorkspaceTarget(value.NodeId, target, value.Response)) return false;
        WorkspaceServiceRegisterWorkspaceResponse inner;
        try { inner = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, null, inner.Error)) return false;
        if (inner.Error is { } error)
            return WorkspaceError(error, WorkspaceMethod.Register) && WorkspaceLimit(error, request) && inner.Audit is null;
        var workspace = inner.Value?.Workspace;
        return NodeShapes.IsValid(request) && workspace is not null && ValidWorkspace(workspace) &&
            workspace.Kind == WorkspaceKind.Registered &&
            (inner.Audit is null || WorkspaceAudit(inner.Audit, [workspace]));
    }

    internal static bool UnregisterWorkspace(FleetServiceUnregisterNodeWorkspaceResponse response, Id target, WorkspaceServiceUnregisterWorkspaceRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return WorkspaceLimit(outer, null);
        if (response.Value is not { HasResponse: true } value || !WorkspaceTarget(value.NodeId, target, value.Response)) return false;
        WorkspaceServiceUnregisterWorkspaceResponse inner;
        try { inner = WorkspaceServiceUnregisterWorkspaceResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, null, inner.Error)) return false;
        if (inner.Error is { } error)
            return WorkspaceError(error, WorkspaceMethod.Unregister) && WorkspaceLimit(error, null) && inner.Audit is null;
        var receipt = inner.Value?.Receipt;
        return NodeShapes.IsValid(request) && receipt is not null && receipt.CommandId is not null &&
            receipt.CommandId.Equals(request.Meta?.CommandId) && receipt.HasEffect && receipt.Effect == EffectCertainty.Happened &&
            inner.Audit is null;
    }

    internal static bool ListWorkspaces(FleetServiceListNodeWorkspacesResponse response, Id target, WorkspaceServiceListWorkspacesRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return WorkspaceLimit(outer, null);
        if (response.Value is not { HasResponse: true } value || !WorkspaceTarget(value.NodeId, target, value.Response)) return false;
        WorkspaceServiceListWorkspacesResponse inner;
        try { inner = WorkspaceServiceListWorkspacesResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error)) return false;
        if (inner.Error is { } error)
            return WorkspaceError(error, WorkspaceMethod.List) && WorkspaceLimit(error, null) && inner.Audit is null;
        if (!NodeShapes.IsValid(request) || inner.CalculateSize() > 131_072 || inner.Value is not { Page: { } page } list ||
            !page.HasHasMore || page.HasMore != (page.HasNextCursor && page.NextCursor.Length > 0) ||
            page.HasNextCursor && page.NextCursor.Length > 2048 ||
            list.Workspaces.Count > (request.Page is { HasLimit: true } requested ? requested.Limit : 100) ||
            list.Workspaces.Any(w => !ValidWorkspace(w) || request.Kinds.Count > 0 && !request.Kinds.Contains(w.Kind)))
            return false;
        var ids = new HashSet<ByteString>();
        return list.Workspaces.All(w => ids.Add(w.WorkspaceId.Value)) && WorkspaceAudit(inner.Audit, list.Workspaces);
    }

    internal static bool GetWorkspace(FleetServiceGetNodeWorkspaceResponse response, Id target, WorkspaceServiceGetWorkspaceRequest request)
    {
        if (!FleetShapes.IsValid(response)) return false;
        if (response.Error is { } outer) return WorkspaceLimit(outer, null);
        if (response.Value is not { HasResponse: true } value || !WorkspaceTarget(value.NodeId, target, value.Response)) return false;
        WorkspaceServiceGetWorkspaceResponse inner;
        try { inner = WorkspaceServiceGetWorkspaceResponse.Parser.ParseFrom(value.Response); }
        catch (InvalidProtocolBufferException) { return false; }
        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error)) return false;
        if (inner.Error is { } error)
            return WorkspaceError(error, WorkspaceMethod.Get) && WorkspaceLimit(error, null) && inner.Audit is null;
        var workspace = inner.Value?.Workspace;
        return NodeShapes.IsValid(request) && workspace is not null && ValidWorkspace(workspace) &&
            workspace.WorkspaceId.Equals(request.WorkspaceId) && WorkspaceAudit(inner.Audit, [workspace]);
    }

    private static bool WorkspaceTarget(Id? actual, Id expected, ByteString bytes) =>
        actual is { Value.Length: 16 } && actual.Equals(expected) && bytes.Length is >= 1 and <= 131_072;

    private static bool WorkspaceLimit(ArcError error, WorkspaceServiceRegisterWorkspaceRequest? request)
    {
        if (!CanonicalLimits(error)) return false;
        if (error.Category != ErrorCategory.Resource || error.Code != "too_large") return true;
        var limit = error.Details?.Limit;
        if (request is not { HasPath: true } || limit?.Maximum?.Value != "4096" || !Token(limit.LimitName) ||
            limit.LimitName is "path_bytes" or "file_write_bytes" or "file_edit_text_bytes" or "file_existing_bytes" or
                "file_edit_result_bytes" or "removal_descendants" or "removal_total_bytes")
            return false;
        try { return StrictUtf8.GetByteCount(request.Path) > 4096; }
        catch (EncoderFallbackException) { return false; }
    }

    private enum WorkspaceMethod { Register, Unregister, List, Get }

    private static bool WorkspaceError(ArcError error, WorkspaceMethod method)
    {
        if (!NodeShapes.IsValid(error) || !CanonicalLimits(error)) return false;
        if (error.Category == ErrorCategory.Internal && error.Code == "internal" &&
            method is WorkspaceMethod.Register or WorkspaceMethod.Unregister &&
            error.Effect == EffectCertainty.Unknown && error.Retry is { Mode: RetryMode.Never, RetryAt: null })
            return true;
        if (error.Category == ErrorCategory.Conflict && error.Code == "command_id_reused")
            return method is WorkspaceMethod.Register or WorkspaceMethod.Unregister && error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.Never, RetryAt: null };
        if (error.Category == ErrorCategory.State && error.Code == "not_found")
            return method is WorkspaceMethod.Get or WorkspaceMethod.Unregister && error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.Never, RetryAt: null } && error.Details?.State?.Resource is { Kind: "workspace" };
        if (error.Category == ErrorCategory.State && error.Code == "in_use")
            return method == WorkspaceMethod.Unregister && error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.AfterTime, RetryAt: not null } && error.Details?.State is not null;
        if (error.Category == ErrorCategory.Validation && error.Code == "invalid_cursor")
            return method == WorkspaceMethod.List && error.Effect == EffectCertainty.DidNotHappen &&
                error.Retry is { Mode: RetryMode.Never, RetryAt: null };
        if (!ReadError(error)) return false;
        return (error.Category, error.Code) switch
        {
            (ErrorCategory.Validation, "path_not_found") => method == WorkspaceMethod.Register,
            (ErrorCategory.Resource, "too_large") => method == WorkspaceMethod.Register,
            (ErrorCategory.Conflict, "file_changed") or (ErrorCategory.State, "file_access_denied") =>
                method is WorkspaceMethod.Register or WorkspaceMethod.Get,
            _ => true,
        };
    }

    private static bool ValidWorkspace(Workspace workspace)
    {
        if (workspace.WorkspaceId is not { Value.Length: 16 } id || id.Value.Span.IndexOfAnyExcept((byte)0) < 0 ||
            !workspace.HasKind || workspace.Kind is < WorkspaceKind.Registered or > WorkspaceKind.Remote ||
            !workspace.HasState || workspace.State is <= WorkspaceState.Unspecified or > WorkspaceState.Archiving ||
            !workspace.HasName || !workspace.HasRootPath || workspace.Name.Length == 0 || workspace.RootPath.Length == 0 ||
            workspace.RootPath.Contains('\0') || workspace.Kind == WorkspaceKind.Registered && workspace.State != WorkspaceState.Active)
            return false;
        try
        {
            if (StrictUtf8.GetByteCount(workspace.RootPath) > 4096 || workspace.Name.EnumerateRunes().Count() > 100 ||
                StrictUtf8.GetByteCount(workspace.Name) == 0) return false;
        }
        catch (EncoderFallbackException) { return false; }
        if (workspace.Git is not { } git) return true;
        if (!git.HasQuality || git.Quality is < GitStatusQuality.Complete or > GitStatusQuality.Truncated) return false;
        return git.Quality == GitStatusQuality.Complete
            ? git.HasDirty && git.HasModifiedFiles && git.HasUntrackedFiles && git.HasLocked
            : !git.HasDirty && !git.HasModifiedFiles && !git.HasUntrackedFiles && !git.HasAhead && !git.HasBehind &&
                !git.HasMergedIntoBase && !git.HasUpstreamDeleted && !git.HasLocked;
    }

    private static bool WorkspaceAudit(FileAuditMetadata? actual, IReadOnlyList<Workspace> workspaces)
    {
        if (actual is not { Observations.Count: 1 }) return false;
        try
        {
            var expected = WorkspaceAuditMetadata.ForRecords(workspaces);
            var a = actual.Observations[0];
            var b = expected.Observations[0];
            return a.Kind == b.Kind && a.HasSizeBytes && a.SizeBytes == b.SizeBytes &&
                a.HasDigestInputBytes && a.DigestInputBytes == b.DigestInputBytes &&
                a.HasItemCount && a.ItemCount == b.ItemCount &&
                CryptographicOperations.FixedTimeEquals(a.Sha256.Span, b.Sha256.Span);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            return false;
        }
    }
}
