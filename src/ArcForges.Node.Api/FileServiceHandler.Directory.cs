// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    // The per-node query instance owns the bounded, expiring cursor snapshots and their HMAC key.
    private readonly WorkspaceFileQueries _queries = new(node.Clock);

    public void Dispose() => _queries.Dispose();

    internal async Task<FileServiceListDirectoryResponse> ListDirectoryAsync(Caller caller, FileServiceListDirectoryRequest request,
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
        var pending = node.Processor.ExecuteAsync(command => ListDirectoryInTransaction(command.Transaction, caller, request, started, limit, token),
            CommitDurability.Full);
        DirectoryOutcome result;
        try
        {
            result = await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveDirectoryPendingAsync(pending);
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

    private DirectoryOutcome ListDirectoryInTransaction(StoreTransaction transaction, Caller caller, FileServiceListDirectoryRequest request,
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
            PermissionMatrix.FileRead + " FileService.ListDirectory", workspace, null, path, decision, outcome, observation);
        DirectoryOutcome Refusal(ArcError error)
        {
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            return new DirectoryOutcome(new FileServiceListDirectoryResponse { Meta = meta, Error = error, Audit = observation });
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
            // Cursor syntax and generation have the dedicated invalid_cursor outcome. Check the other request
            // fields with it absent, then let the query verify the original authenticated cursor.
            var shaped = request.Clone();
            shaped.ClearCursor();
            if (request.Path is { HasPath: true } supplied && StrictUtf8.GetByteCount(supplied.Path) > 4096)
            {
                shaped.Path.Path = "x";
                return Refusal(workspace is not null && request.Meta?.CommandId is null && NodeShapes.IsValid(shaped)
                    ? TooLarge(correlation)
                    : Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            if (!NodeShapes.IsValid(shaped) || request.Meta?.CommandId is not null || workspace is null ||
                request.Path is not { HasPath: true } selected || request.HasPageSize && request.PageSize is < 1 or > 128)
            {
                return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation));
            }

            path = selected.Path;
            CheckAuthority(transaction, caller);
            CheckBudget();
            using var use = _workspaces.OpenForUse(transaction, workspace, beforeUse: value => CheckAuthority(value, caller), token);
            AfterWorkspaceSnapshotForTests?.Invoke();
            CheckBudget();
            var page = _queries.ListDirectory(use.Root, workspace, DirectoryCallerBinding(caller.CenterCaller!), path,
                request.HasPageSize ? checked((int)request.PageSize) : 100, request.HasCursor ? request.Cursor : null, token);
            observation = page.Audit;
            CheckBudget();
            CheckAuthority(transaction, caller);
            Audit(PermissionDecision.Allow, "listed");
            return new DirectoryOutcome(new FileServiceListDirectoryResponse { Meta = meta, Value = page.Value, Audit = observation });
        }
        catch (EncoderFallbackException)
        {
            path = null;
            return Refusal(Error(ErrorCategory.Validation, "invalid_argument", "path: utf8", correlation));
        }
        catch (FilePolicyException refusal)
        {
            Audit(PermissionDecision.Deny, "refused: " + refusal.Reason);
            return new DirectoryOutcome(new FileServiceListDirectoryResponse
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
                return new DirectoryOutcome(Abort: new OperationCanceledException(token));
            }

            var error = failure.Reason switch
            {
                "invalid_cursor" => NodeErrors.InvalidCursor(),
                "path_not_directory" => Error(ErrorCategory.Validation, "path_not_found", "path", correlation),
                "directory_arguments" => Error(ErrorCategory.Validation, "invalid_argument", "request: invalid_argument", correlation),
                "directory_changed" => Error(ErrorCategory.Conflict, "file_changed", "directory_changed", correlation),
                _ => Error(ErrorCategory.State, "file_access_denied", "directory_enumeration_unavailable", correlation),
            };
            error.CorrelationId = correlation.Clone();
            return Refusal(error);
        }
        catch (RoutedAbortException abort)
        {
            Audit(PermissionDecision.Deny, "refused: routed_call_ended");
            return new DirectoryOutcome(Abort: abort);
        }
        catch (OperationCanceledException cancelled)
        {
            Audit(PermissionDecision.Deny, "refused: cancelled");
            return new DirectoryOutcome(Abort: cancelled);
        }
        catch (Exception exception) when (exception is RegisteredWorkspaceException or WorkspacePathException or UnauthorizedAccessException or IOException or ArgumentException)
        {
            return Refusal(Failure(exception, correlation));
        }
    }

    private static byte[] DirectoryCallerBinding(CenterCaller caller)
    {
        if (CenterRouting.Shape(caller) is not null)
        {
            throw new FilePolicyException("center_caller_incomplete");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("ArcForges directory cursor caller v1\0"u8);
        hash.AppendData([(byte)caller.Kind]);
        hash.AppendData(caller.AccountId.Value.Span);
        if (caller.Kind == CenterCallerKind.AccountSession)
        {
            hash.AppendData(caller.UserId.Value.Span);
            hash.AppendData(caller.SessionId.Value.Span);
        }
        else
        {
            hash.AppendData(caller.RelayingNodeId.Value.Span);
            hash.AppendData([(byte)caller.LocalOrigin]);
            hash.AppendData(caller.LocalSessionId.Value.Span);
        }

        return hash.GetHashAndReset();
    }

    private async Task ObserveDirectoryPendingAsync(Task<DirectoryOutcome> pending)
    {
        try
        {
            _ = await pending.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            node.Log.Error("api.file.directory.audit_failed");
        }
    }

    private sealed record DirectoryOutcome(FileServiceListDirectoryResponse? Response = null, Exception? Abort = null, string? PolicyReason = null);
}
