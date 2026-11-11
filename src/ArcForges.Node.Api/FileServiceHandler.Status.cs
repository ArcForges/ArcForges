// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    // Coordinates a real SQLite audit failure in an isolated channel test.
    internal Action? StatusBeforeAuditForTests { get; set; }

    /// <summary>Reads journal metadata only for its verified original caller; it never retries an effect.</summary>
    internal async Task<FileServiceGetFileOperationResponse> GetFileOperationAsync(Caller caller, FileServiceGetFileOperationRequest request,
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
        var pending = node.Processor.ExecuteAsync(command => GetFileOperationInTransaction(command.Transaction, caller, request, started, limit, token),
            CommitDurability.Full);
        StatusOutcome result;
        try
        {
            result = await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveStatusPendingAsync(pending);
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

    private StatusOutcome GetFileOperationInTransaction(StoreTransaction transaction, Caller caller, FileServiceGetFileOperationRequest request,
        long started, TimeSpan limit, CancellationToken token)
    {
        var routed = caller.Routed!;
        var correlation = routed.Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        byte[]? workspace = null;
        string? path = null;

        void Audit(PermissionDecision decision, string outcome)
        {
            StatusBeforeAuditForTests?.Invoke();
            AuditLog.AppendFileWorkspace(transaction, caller.Actor,
                PermissionMatrix.FileRead + " FileService.GetFileOperation", workspace, null, path, decision, outcome, null);
        }
        StatusOutcome Refusal(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            Audit(PermissionDecision.Deny, "refused: " + error.Code);
            return new StatusOutcome(new FileServiceGetFileOperationResponse { Meta = meta, Error = error });
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
            CheckBudget();
            if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not null ||
                Validation.RequiredId(request.OperationCommandId, "operation_command_id") is not null)
            {
                return Refusal(NodeErrors.InvalidArgument("operation_command_id: valid ID and no command_id for a read"));
            }

            CheckAuthority(transaction, caller);
            CheckBudget();
            var operation = FileMutationJournal.GetForCaller(transaction, request.OperationCommandId.Value.Span, caller.CenterCaller!);
            CheckBudget();
            CheckAuthority(transaction, caller);
            if (operation is null)
            {
                return Refusal(NodeErrors.NotFound("file_operation", request.OperationCommandId.Value.Span));
            }

            if (!NodeShapes.IsValid(operation) || !operation.CommandId.Equals(request.OperationCommandId))
            {
                throw new InvalidDataException("Invalid stored file operation metadata.");
            }

            if (operation.WorkspacePath is { } target)
            {
                workspace = target.WorkspaceId.Value.ToByteArray();
                path = target.Path;
            }

            CheckBudget();
            Audit(PermissionDecision.Allow, "shown");
            return new StatusOutcome(new FileServiceGetFileOperationResponse
            {
                Meta = meta,
                Value = new FileServiceGetFileOperationValue { Operation = operation },
            });
        }
        catch (FilePolicyException refusal)
        {
            Audit(PermissionDecision.Deny, "refused: " + refusal.Reason);
            return new StatusOutcome(new FileServiceGetFileOperationResponse
            {
                Meta = meta,
                Error = Error(ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileRead, correlation),
            }, PolicyReason: refusal.Reason);
        }
        catch (RoutedAbortException abort)
        {
            Audit(PermissionDecision.Deny, "refused: routed_call_ended");
            return new StatusOutcome(Abort: abort);
        }
        catch (OperationCanceledException cancelled)
        {
            Audit(PermissionDecision.Deny, "refused: cancelled");
            return new StatusOutcome(Abort: cancelled);
        }
    }

    private async Task ObserveStatusPendingAsync(Task<StatusOutcome> pending)
    {
        try
        {
            _ = await pending.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            node.Log.Error("api.file.status.audit_failed");
        }
    }

    private sealed record StatusOutcome(FileServiceGetFileOperationResponse? Response = null, Exception? Abort = null, string? PolicyReason = null);
}
