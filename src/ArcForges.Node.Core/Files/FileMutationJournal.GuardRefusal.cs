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
    /// <summary>
    /// Persists an actually established pre-effect native guard refusal for the original request. The coordinator must
    /// prove no effect permission was sent and any registered child has ended before invoking this method.
    /// </summary>
    internal static byte[] CompleteKnownGuardUnavailable(StoreTransaction transaction, FileOperationKind kind,
        ReadOnlySpan<byte> commandId, CenterCaller caller, ReadOnlySpan<byte> transmitted)
    {
        RequireFull(transaction);
        if (FindExisting(transaction, kind, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            throw new InvalidOperationException("The original file command and caller do not match.");
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged ||
            !FileEffectWorker.MarkEndedIfObserved(transaction, commandId))
            throw new InvalidOperationException("A live or changed file operation cannot be settled as a refusal.");
        var error = GuardUnavailable(row);
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known write guard refusal.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known edit guard refusal.");
            outcome = response.ToByteArray();
        }
        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during guard refusal settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Deny, "refused: enforcement_unavailable", null);
        return outcome;
    }

    private static ArcError GuardUnavailable(JournalRow row) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "enforcement_unavailable",
        MessageKey = "error.resource.enforcement_unavailable",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_guard_unavailable" } },
    };
}
