// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>Only observations known before a target effect may use these settlements.</summary>
internal enum ApprovedFileRefusal
{
    PolicyDenied,
    ApprovalExpired,
    EnforcementUnavailable,
    TargetChanged,
}

internal static partial class FileMutationJournal
{
    /// <summary>
    /// Records a proven refusal without a target effect. A previously PREPARED journal is deliberately not adopted:
    /// it could be an interrupted or in-flight effect. Only its own coordinator may settle that attempt.
    /// </summary>
    internal static byte[] RecordApprovedPreEffectRefusal(StoreTransaction transaction, ReadOnlySpan<byte> approvalId,
        ApprovedFileRefusal reason)
    {
        RequireFull(transaction);
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId)
            ?? throw new InvalidOperationException("The approved file binding is unavailable.");
        if (!plan.Active || ReadRow(transaction, plan.Intent.CommandId) is not null ||
            transaction.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", plan.Intent.CommandId)) is not null)
            throw new InvalidOperationException("A prior file attempt cannot be settled as a new pre-effect refusal.");
        InsertApprovedIntent(transaction, plan);
        return CompleteApprovedRefusal(transaction, plan, reason);
    }

    /// <summary>
    /// The same coordinator that committed PREPARED can call this before its first target effect, while it still owns
    /// its guards. Do not use it for a different or recovered PREPARED attempt.
    /// </summary>
    internal static byte[] CompleteApprovedPreparedRefusal(StoreTransaction transaction, ReadOnlySpan<byte> approvalId,
        ApprovedFileRefusal reason)
    {
        RequireFull(transaction);
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId)
            ?? throw new InvalidOperationException("The approved file binding is unavailable.");
        return CompleteApprovedRefusal(transaction, plan, reason);
    }

    private static byte[] CompleteApprovedRefusal(StoreTransaction transaction, PrivateStageApprovedPlan plan,
        ApprovedFileRefusal reason)
    {
        var row = ReadRow(transaction, plan.Intent.CommandId)
            ?? throw new InvalidOperationException("The prepared file intent is unavailable.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null || !row.Held || row.Acknowledged ||
            row.Kind != plan.Intent.Kind || !CryptographicOperations.FixedTimeEquals(row.RequestSha256, plan.RequestSha256) ||
            !CenterRouting.SameFileCaller(row.Caller, plan.Intent.Caller))
            throw new InvalidOperationException("The prepared intent does not match the approved command.");

        var error = ApprovedRefusal(row, reason);
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid approved write refusal.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid approved edit refusal.");
            outcome = response.ToByteArray();
        }

        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed before refusal settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        transaction.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id AND active = 1;",
            ("$id", row.CommandId));
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Deny, "refused: " + error.Code, null);
        return outcome;
    }

    private static ArcError ApprovedRefusal(JournalRow row, ApprovedFileRefusal reason)
    {
        var (category, code, detail) = reason switch
        {
            ApprovedFileRefusal.PolicyDenied => (ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite),
            ApprovedFileRefusal.ApprovalExpired => (ErrorCategory.State, "invalid_state", "approval_expired"),
            ApprovedFileRefusal.EnforcementUnavailable => (ErrorCategory.Resource, "enforcement_unavailable", "file_guard_unavailable"),
            ApprovedFileRefusal.TargetChanged => (ErrorCategory.Conflict, "file_changed", "file_identity_changed"),
            _ => throw new ArgumentOutOfRangeException(nameof(reason)),
        };
        return new ArcError
        {
            Category = category,
            Code = code,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = detail } },
        };
    }
}
