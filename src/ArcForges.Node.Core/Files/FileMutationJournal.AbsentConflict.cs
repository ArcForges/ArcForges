// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

internal static partial class FileMutationJournal
{
    /// <summary>
    /// Records a native exclusive-create collision against the same prepared parent and stage. The operating-system
    /// FILE_CREATE result proves that this attempt created no target. A caller cannot substitute another operation,
    /// caller, path, exact request or stage to settle a journal.
    /// </summary>
    internal static byte[] CompleteKnownExpectedAbsentConflict(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        CenterCaller caller, ReadOnlySpan<byte> transmitted, WorkspaceCreateCollisionException collision)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(collision);
        if (FindExisting(transaction, FileOperationKind.Write, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            throw new InvalidOperationException("The original file command and caller do not match.");
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        return CompleteCheckedAbsentConflict(transaction, row, collision);
    }

    /// <summary>Records the same real exclusive-create collision for the bound local HUMAN-approved request.</summary>
    internal static byte[] CompleteApprovedAbsentConflict(StoreTransaction transaction, ReadOnlySpan<byte> approvalId,
        WorkspaceCreateCollisionException collision)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(collision);
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId)
            ?? throw new InvalidOperationException("The approved file binding is unavailable.");
        var row = ReadRow(transaction, plan.Intent.CommandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.Kind != plan.Intent.Kind || !CryptographicOperations.FixedTimeEquals(row.RequestSha256, plan.RequestSha256) ||
            !CenterRouting.SameFileCaller(row.Caller, plan.Intent.Caller))
            throw new InvalidOperationException("The collision does not bind the approved request.");
        return CompleteCheckedAbsentConflict(transaction, row, collision);
    }

    private static byte[] CompleteCheckedAbsentConflict(StoreTransaction transaction, JournalRow row, WorkspaceCreateCollisionException collision)
    {
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged ||
            !row.ExpectedAbsent || !string.Equals(row.Path, collision.RelativePath, StringComparison.Ordinal))
            throw new InvalidOperationException("Only the matching absent-target intent can record this collision.");
        var parent = RegisteredWorkspaces.RootIdentity.Encode(collision.Parent);
        using (var select = transaction.CreateCommand("""
            SELECT identity_platform, parent_identity, intended_stage_identity FROM file_operation_journal WHERE command_id = $id;
            """))
        {
            select.Parameters.AddWithValue("$id", row.CommandId);
            using var values = select.ExecuteReader();
            if (!values.Read() || values.GetInt32(0) != parent.Platform || values.GetInt32(0) != collision.StageIdentity.Platform ||
                !CryptographicOperations.FixedTimeEquals((byte[])values.GetValue(1), parent.Bytes) ||
                !CryptographicOperations.FixedTimeEquals((byte[])values.GetValue(2), collision.StageIdentity.Bytes))
                throw new InvalidOperationException("The native collision is not bound to the prepared parent and stage.");
        }

        var response = new FileServiceWriteFileResponse
        {
            Meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } },
            Error = ExpectedAbsentConflict(row),
        };
        if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid absent-target collision outcome.");
        var outcome = response.ToByteArray();
        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during collision settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        if (PrivateStageRegistry.HasSchema(transaction))
            transaction.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id AND active = 1;",
                ("$id", row.CommandId));
        AuditLog.AppendFileWorkspace(transaction, Actor(row), "file.write FileService.WriteFile", row.WorkspaceId, null, row.Path,
            PermissionDecision.Deny, "refused: file_changed", null);
        return outcome;
    }

    private static ArcError ExpectedAbsentConflict(JournalRow row) => new()
    {
        Category = ErrorCategory.Conflict,
        Code = "file_changed",
        MessageKey = "error.conflict.file_changed",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "expected_absent_conflict" } },
    };

    private static ArcError ReadKnownFileRefusal(JournalRow row, ArcError error)
    {
        if (row.ExpectedAbsent && row.Kind == FileOperationKind.Write && NodeShapes.IsValid(error) &&
            error.Equals(ExpectedAbsentConflict(row)))
            return error.Clone();
        if (NodeShapes.IsValid(error) &&
            (error.Equals(AuthorityRefusal(row, approvalUnavailable: false)) ||
             error.Equals(AuthorityRefusal(row, approvalUnavailable: true))))
            return error.Clone();
        if (NodeShapes.IsValid(error) && error.Equals(GuardUnavailable(row)))
            return error.Clone();
        foreach (var reason in new[] { "hash_mismatch", "file_identity_changed", "directory_identity_changed", "root_changed" })
            if (NodeShapes.IsValid(error) && error.Equals(TargetChanged(row, reason))) return error.Clone();
        foreach (var reason in Enum.GetValues<ApprovedFileRefusal>())
        {
            if (NodeShapes.IsValid(error) && error.Equals(ApprovedRefusal(row, reason)))
                return error.Clone();
        }
        return ReadKnownExistingFileTooLarge(row, error);
    }
}
