// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Core.Files;

internal static partial class FileMutationJournal
{
    /// <summary>
    /// Records an actually observed, guarded existing-file size refusal after PREPARED and before any target effect.
    /// The coordinator must retain the exact target guard and prove no effect began. This method observes that guard,
    /// binds its native identity to the prepared target, and persists only the closed limit and request binding.
    /// </summary>
    internal static byte[] CompleteKnownExistingFileTooLarge(StoreTransaction transaction, FileOperationKind kind,
        ReadOnlySpan<byte> commandId, CenterCaller caller, ReadOnlySpan<byte> transmitted, WorkspaceWriteGuard target,
        CancellationToken cancellationToken)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (FindExisting(transaction, kind, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            throw new InvalidOperationException("The original file command and caller do not match.");
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged)
            throw new InvalidOperationException("Only a prepared, held file intent can be refused before effect.");
        var identity = RegisteredWorkspaces.RootIdentity.Encode(target.ObjectIdentity, directory: false);
        var recorded = transaction.Scalar("SELECT target_identity FROM file_operation_journal WHERE command_id = $id;", ("$id", row.CommandId)) as byte[];
        if (recorded is null || !recorded.AsSpan().SequenceEqual(identity.Bytes))
            throw new InvalidOperationException("The guarded target does not match the prepared file identity.");
        if (target.ObserveLength(cancellationToken) <= MaximumFileBytes)
            throw new InvalidOperationException("The held target does not exceed the existing-file bound.");

        var error = ExistingFileTooLarge(row);
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known write refusal.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid known edit refusal.");
            outcome = response.ToByteArray();
        }

        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during refusal settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Deny, "refused: too_large", null);
        return outcome;
    }

    private static ArcError ExistingFileTooLarge(JournalRow row) => new()
    {
        Category = ErrorCategory.Resource,
        Code = "too_large",
        MessageKey = "error.resource.too_large",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
        Details = new ErrorDetails
        {
            Limit = new LimitFailure
            {
                LimitName = "file_existing_bytes",
                Maximum = new WireDecimal { Value = "4194304" },
            },
        },
    };

    private static ArcError ReadKnownExistingFileTooLarge(JournalRow row, ArcError error)
    {
        // Current producer's recorded refusal has a fixed canonical envelope. A malformed or noncanonical stored
        // Decimal is never accepted merely because the published 450.1 validator accepts its shape.
        if (row.ExpectedAbsent || !NodeShapes.IsValid(error) || !error.Equals(ExistingFileTooLarge(row)))
            throw new InvalidDataException("Invalid known existing-file size refusal.");
        return error.Clone();
    }
}
