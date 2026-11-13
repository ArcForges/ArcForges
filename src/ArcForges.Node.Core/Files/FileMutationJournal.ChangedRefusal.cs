// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

internal static partial class FileMutationJournal
{
    /// <summary>Persists a checked pre-effect target conflict only after the owned worker can no longer act.</summary>
    internal static byte[] CompleteKnownTargetChanged(StoreTransaction transaction, FileOperationKind kind,
        ReadOnlySpan<byte> commandId, CenterCaller caller, ReadOnlySpan<byte> transmitted, string reason)
    {
        RequireFull(transaction);
        if (reason is not ("hash_mismatch" or "file_identity_changed" or "directory_identity_changed" or "root_changed"))
            throw new ArgumentException("A closed observed conflict reason is required.", nameof(reason));
        if (FindExisting(transaction, kind, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            throw new InvalidOperationException("The original file command and caller do not match.");
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged ||
            !FileEffectWorker.MarkEndedIfObserved(transaction, commandId))
            throw new InvalidOperationException("A live or changed file operation cannot be settled as a refusal.");
        var error = TargetChanged(row, reason);
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known write conflict.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known edit conflict.");
            outcome = response.ToByteArray();
        }
        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during conflict settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Deny, "refused: file_changed", null);
        return outcome;
    }

    private static ArcError TargetChanged(JournalRow row, string reason) => new()
    {
        Category = ErrorCategory.Conflict,
        Code = "file_changed",
        MessageKey = "error.conflict.file_changed",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = reason } },
    };
}
