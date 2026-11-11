// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    internal async Task<FileServiceSearchFilesResponse> SearchAsync(Caller caller, FileServiceSearchFilesRequest request,
        CancellationToken cancellationToken)
    {
        var routed = caller.Routed ?? throw new InvalidOperationException("A file operation requires a verified routed caller.");
        var limit = routed.RemainingFileOperation();
        if (limit <= TimeSpan.Zero)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        var started = node.Clock.GetTimestamp();
        using var deadline = new CancellationTokenSource(limit, node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var token = linked.Token;
        var pending = node.Processor.ExecuteAsync(command => SearchInTransaction(command.Transaction, caller, request, started, limit, token),
            CommitDurability.Full);
        SearchOutcome result;
        try
        {
            result = await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveSearchPendingAsync(pending);
            throw;
        }

        if (Expired(started, limit, token))
        {
            throw new OperationCanceledException(token);
        }

        if (result.Abort is RoutedAbortException routedAbort)
        {
            throw routedAbort;
        }

        if (result.Abort is OperationCanceledException cancelled)
        {
            throw cancelled;
        }

        if (result.PolicyReason is { } reason)
        {
            routed.Refused(PermissionMatrix.FileRead, reason);
            routed.MarkAudited();
        }

        return result.Response!;
    }

    private SearchOutcome SearchInTransaction(StoreTransaction transaction, Caller caller, FileServiceSearchFilesRequest request,
        long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        byte[]? workspace = request.Path?.WorkspaceId is { Value.Length: 16 } id &&
            id.Value.Span.IndexOfAnyExcept((byte)0) >= 0 ? id.Value.ToByteArray() : null;
        string? path = null;
        FileAuditMetadata? observation = null;

        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, caller.Actor,
            PermissionMatrix.FileRead + " FileService.SearchFiles", workspace, null, path, decision, outcome, observation);
        SearchOutcome Refusal(ArcError error)
        {
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            return new SearchOutcome(new FileServiceSearchFilesResponse { Meta = meta, Error = error, Audit = observation });
        }

        void CheckBudget()
        {
            if (Expired(started, limit, token))
            {
                throw new OperationCanceledException(token);
            }
        }

        try
        {
            if (request.Path is { HasPath: true } attempted && StrictUtf8.GetByteCount(attempted.Path) <= 4096)
            {
                path = attempted.Path;
            }

            CheckBudget();
            if (request.Path is { HasPath: true } supplied && StrictUtf8.GetByteCount(supplied.Path) > 4096)
            {
                var bounded = request.Clone();
                bounded.Path.Path = "x";
                return Refusal(workspace is not null && request.Meta?.CommandId is null && NodeShapes.IsValid(bounded)
                    ? TooLarge(correlation)
                    : Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not null || workspace is null ||
                request.Path is not { HasPath: true } selected || !request.HasPattern || !request.HasMode ||
                request.HasMaxMatches && request.MaxMatches is < 1 or > WorkspaceFileQueries.MaximumMatches ||
                request.HasMaxScanBytes && request.MaxScanBytes is < 1 or > WorkspaceFileQueries.MaximumScanBytes)
            {
                return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            path = selected.Path;
            CheckAuthority(transaction, caller);
            CheckBudget();
            using var use = _workspaces.OpenForUse(transaction, workspace, beforeUse: value => CheckAuthority(value, caller), token);
            AfterWorkspaceSnapshotForTests?.Invoke();
            CheckBudget();
            var result = _queries.Search(use.Root, path, request.Pattern, request.Mode,
                request.HasMaxMatches ? checked((int)request.MaxMatches) : WorkspaceFileQueries.MaximumMatches,
                request.HasMaxScanBytes ? request.MaxScanBytes : WorkspaceFileQueries.MaximumScanBytes, token);
            observation = result.Audit;
            CheckBudget();
            CheckAuthority(transaction, caller);
            Audit(PermissionDecision.Allow, "searched");
            return new SearchOutcome(new FileServiceSearchFilesResponse { Meta = meta, Value = result.Value, Audit = observation });
        }
        catch (EncoderFallbackException)
        {
            path = null;
            return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: utf8", correlation));
        }
        catch (FilePolicyException refusal)
        {
            Audit(PermissionDecision.Deny, "refused: " + refusal.Reason);
            return new SearchOutcome(new FileServiceSearchFilesResponse
            {
                Meta = meta,
                Error = Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRead, correlation),
                Audit = observation,
            }, PolicyReason: refusal.Reason);
        }
        catch (WorkspaceQueryException failure)
        {
            observation = failure.Audit;
            if (failure.Reason is "query_cancelled" or "query_deadline")
            {
                Audit(PermissionDecision.Deny, "refused: cancelled");
                return new SearchOutcome(Abort: new OperationCanceledException(token));
            }

            var error = failure.Reason switch
            {
                "pattern_length" or "pattern_invalid_utf8" or "pattern_unsupported" or "pattern_mode" or "regex_scalar_boundary" =>
                    Error(ErrorCategory.Validation, "invalid_argument", "pattern: " + failure.Reason, correlation),
                "query_limit_invalid" => Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation),
                _ => Failure(new WorkspacePathException(failure.Reason), correlation),
            };
            return Refusal(error);
        }
        catch (RoutedAbortException abort)
        {
            Audit(PermissionDecision.Deny, "refused: routed_call_ended");
            return new SearchOutcome(Abort: abort);
        }
        catch (OperationCanceledException cancelled)
        {
            Audit(PermissionDecision.Deny, "refused: cancelled");
            return new SearchOutcome(Abort: cancelled);
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return Refusal(Failure(exception, correlation));
        }
    }

    private async Task ObserveSearchPendingAsync(Task<SearchOutcome> pending)
    {
        try
        {
            _ = await pending.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            node.Log.Error("api.file.search.audit_failed");
        }
    }

    private sealed record SearchOutcome(FileServiceSearchFilesResponse? Response = null, Exception? Abort = null, string? PolicyReason = null);
}
