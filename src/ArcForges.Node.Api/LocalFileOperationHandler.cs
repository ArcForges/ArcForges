// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Grpc.Core;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

/// <summary>
/// Local recovery management only. The connection's verified Hello/peer classification determines HUMAN; no request
/// field can assert it. The other FileService methods remain unimplemented on this local endpoint.
/// </summary>
internal sealed class LocalFileOperationHandler(NodeRuntime node, ClientSessions sessions) : FileService.FileServiceBase
{
    private const string Service = "arcforges.node.v1.FileService";
    private readonly ApiCommands _api = new(node, sessions, Service);

    public override async Task<FileServiceGetFileOperationResponse> GetFileOperation(FileServiceGetFileOperationRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var caller = _api.CallerOf(context);
        var correlation = Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        FileServiceGetFileOperationResponse Failure(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            return new FileServiceGetFileOperationResponse { Meta = meta, Error = error };
        }

        if (_api.Stopping() is { } stopping)
        {
            await AuditRefusalAsync(caller, "GetFileOperation", "node_stopping", context.CancellationToken).ConfigureAwait(false);
            return Failure(stopping);
        }
        if (!IsHuman(caller))
        {
            await AuditRefusalAsync(caller, "GetFileOperation", "permission_denied", context.CancellationToken).ConfigureAwait(false);
            return Failure(NodeErrors.PermissionDenied("file_operation.show"));
        }

        if (!NodeShapes.IsValid(request) || request.Meta?.CommandId is not null ||
            Validation.RequiredId(request.OperationCommandId, "operation_command_id") is not null)
        {
            await AuditRefusalAsync(caller, "GetFileOperation", "invalid_argument", context.CancellationToken).ConfigureAwait(false);
            return Failure(NodeErrors.InvalidArgument("operation_command_id: a valid ID and no command_id for a read"));
        }

        var pending = node.Processor.ExecuteAsync(command =>
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var operation = FileMutationJournal.GetForVerifiedHuman(command.Transaction, request.OperationCommandId.Value.Span);
            var path = operation?.WorkspacePath;
            AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, "file.show FileService.GetFileOperation",
                path?.WorkspaceId?.Value.ToByteArray(), null, path?.Path, operation is null ? PermissionDecision.Deny : PermissionDecision.Allow,
                operation is null ? "refused: not_found" : "shown", null);
            var warnings = operation is null or { State: FileOperationState.Unknown }
                ? PrivateStageLocations.ForVerifiedHuman(command.Transaction, request.OperationCommandId.Value.Span, context.CancellationToken)
                    .Select(PrivateStageLocations.ToWarning).ToArray()
                : Array.Empty<string>();
            return (Operation: operation, Warnings: warnings);
        }, CommitDurability.Full);
        (FileOperation? Operation, string[] Warnings) value;
        try
        {
            value = await pending.WaitAsync(context.CancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveAsync(pending);
            throw;
        }

        meta.Warnings.Add(value.Warnings);
        if (value.Operation is null) return Failure(NodeErrors.NotFound("file_operation", request.OperationCommandId.Value.Span));
        return new FileServiceGetFileOperationResponse { Meta = meta, Value = new FileServiceGetFileOperationValue { Operation = value.Operation } };
    }

    public override async Task<FileServiceAcknowledgeFileOperationResponse> AcknowledgeFileOperation(
        FileServiceAcknowledgeFileOperationRequest request, ServerCallContext context)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        var caller = _api.CallerOf(context);
        var correlation = Correlation(request.Meta);
        var meta = new ResponseMeta { CorrelationId = correlation.Clone() };
        FileServiceAcknowledgeFileOperationResponse Failure(ArcError error)
        {
            RoutedFileErrors.Complete(error, request.Meta, correlation, node.Clock);
            return new FileServiceAcknowledgeFileOperationResponse { Meta = meta, Error = error };
        }

        if (_api.Stopping() is { } stopping)
        {
            await AuditRefusalAsync(caller, "AcknowledgeFileOperation", "node_stopping", context.CancellationToken).ConfigureAwait(false);
            return Failure(stopping);
        }
        if (!IsHuman(caller))
        {
            await AuditRefusalAsync(caller, "AcknowledgeFileOperation", "permission_denied", context.CancellationToken).ConfigureAwait(false);
            return Failure(NodeErrors.PermissionDenied("file_operation.acknowledge"));
        }

        if (!NodeShapes.IsValid(request) || Validation.CommandId(request.Meta) is not null ||
            Validation.RequiredId(request.OperationCommandId, "operation_command_id") is not null ||
            !request.HasOperationDigest || request.OperationDigest.Length != 32)
        {
            await AuditRefusalAsync(caller, "AcknowledgeFileOperation", "invalid_argument", context.CancellationToken).ConfigureAwait(false);
            return Failure(NodeErrors.InvalidArgument("request: command and operation IDs and 32-byte digest are required"));
        }

        var pending = _api.IdempotentAsync(request, request.Meta!, caller, "AcknowledgeFileOperation",
            FileServiceAcknowledgeFileOperationResponse.Parser, Failure, command =>
            {
                context.CancellationToken.ThrowIfCancellationRequested();
                var result = FileMutationJournal.AcknowledgeFromVerifiedHuman(command.Transaction, request.OperationCommandId.Value.Span,
                    request.OperationDigest.Span, caller.Actor);
                if (result != FileJournalAcknowledgment.Acknowledged)
                {
                    return Failure(result switch
                    {
                        FileJournalAcknowledgment.NotFound => NodeErrors.NotFound("file_operation", request.OperationCommandId.Value.Span),
                        FileJournalAcknowledgment.DigestMismatch => DigestMismatch(),
                        _ => NodeErrors.InvalidArgument("operation.state: UNKNOWN and held required"),
                    });
                }

                var operation = FileMutationJournal.GetForVerifiedHuman(command.Transaction, request.OperationCommandId.Value.Span)
                    ?? throw new InvalidDataException("An acknowledged journal disappeared.");
                return new FileServiceAcknowledgeFileOperationResponse
                {
                    Meta = meta,
                    Value = new FileServiceAcknowledgeFileOperationValue
                    {
                        Receipt = new Receipt { CommandId = request.Meta!.CommandId.Clone(), Effect = EffectCertainty.Happened },
                        Operation = operation,
                    },
                };
            });
        try
        {
            return (await pending.WaitAsync(context.CancellationToken).ConfigureAwait(false)).Response;
        }
        catch (OperationCanceledException)
        {
            _ = ObserveAsync(pending);
            throw;
        }
    }

    private Id Correlation(RequestMeta? meta) =>
        Validation.RequiredId(meta?.CorrelationId, "correlation_id") is null ? meta!.CorrelationId.Clone() : CommandIds.New(node.Clock);

    private static bool IsHuman(Caller caller) => caller.Session is { Origin: Origin.Human } && caller.Origin == Origin.Human;

    private async Task AuditRefusalAsync(Caller caller, string method, string reason, CancellationToken token)
    {
        var pending = node.Processor.ExecuteAsync(command =>
        {
            token.ThrowIfCancellationRequested();
            AuditLog.AppendFileWorkspace(command.Transaction, caller.Actor, "file.local FileService." + method,
                null, null, null, PermissionDecision.Deny, "refused: " + reason, null);
            return 0;
        }, CommitDurability.Full);
        try
        {
            await pending.WaitAsync(token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = ObserveAsync(pending);
            throw;
        }
    }

    private static async Task ObserveAsync<T>(Task<T> pending)
    {
        try { _ = await pending.ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OutOfMemoryException) { }
    }

    private static ArcError DigestMismatch() => new()
    {
        Category = ErrorCategory.Conflict,
        Code = "digest_mismatch",
        MessageKey = "error.conflict.digest_mismatch",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Details = new ErrorDetails { State = new StateFailure { State = "file_operation", Reason = "operation_digest_mismatch" } },
    };
}
