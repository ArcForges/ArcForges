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
    /// Settles a policy recheck that actually refused a prepared operation before any target effect. The coordinator
    /// invokes this only at its initial pre-effect check, after binding the exact caller and transmitted request.
    /// A missing durable approval implementation is an enforcement refusal, never an approval.
    /// </summary>
    internal static byte[] CompleteKnownAuthorityRefusal(StoreTransaction transaction, FileOperationKind kind,
        ReadOnlySpan<byte> commandId, CenterCaller caller, ReadOnlySpan<byte> transmitted, bool approvalUnavailable)
    {
        RequireFull(transaction);
        if (FindExisting(transaction, kind, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            throw new InvalidOperationException("The original file command and caller do not match.");
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged)
            throw new InvalidOperationException("Only a prepared, held file intent can be refused before effect.");

        var error = AuthorityRefusal(row, approvalUnavailable);
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known write authority refusal.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known edit authority refusal.");
            outcome = response.ToByteArray();
        }

        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during authority refusal settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Deny, "refused: " + error.Code, null);
        return outcome;
    }

    private static ArcError AuthorityRefusal(JournalRow row, bool approvalUnavailable)
    {
        var category = approvalUnavailable ? ErrorCategory.Resource : ErrorCategory.Authorization;
        var code = approvalUnavailable ? "enforcement_unavailable" : "permission_denied";
        return new ArcError
        {
            Category = category,
            Code = code,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
            Details = new ErrorDetails
            {
                State = new StateFailure
                {
                    State = "file",
                    Reason = approvalUnavailable ? "file_approval_unavailable" : PermissionMatrix.FileWrite,
                }
            },
        };
    }
}
