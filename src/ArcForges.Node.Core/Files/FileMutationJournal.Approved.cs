// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

internal enum ApprovedFilePreparation
{
    Prepared,
    Existing,
    InvalidApproval,
    Expired,
    ClockUncertain,
    WorkspaceHeld,
    Conflict,
}

internal static partial class FileMutationJournal
{
    /// <summary>
    /// Adopts only the existing metadata-only approved command and its exact guarded stages into PREPARED. The current
    /// policy and local HUMAN decision authority must also be checked by the effect coordinator. An existing journal is
    /// never prepared again; after interruption the normal startup recovery makes PREPARED UNKNOWN.
    /// </summary>
    internal static (ApprovedFilePreparation Status, PrivateStageApprovedPlan? Plan) PrepareApproved(
        StoreTransaction transaction, ReadOnlySpan<byte> approvalId, WorkspacePath root, WorkspaceWriteGuard? target,
        RecoveredPrivateStage? original, RecoveredPrivateStage intended, CancellationToken cancellationToken)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(intended);
        StoreIds.Validate(approvalId, nameof(approvalId));
        var sample = RoutedFileValidationTime.Advance(transaction);
        if (!sample.Healthy) return (ApprovedFilePreparation.ClockUncertain, null);
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId);
        if (plan is null) return (ApprovedFilePreparation.InvalidApproval, null);
        var intent = plan.Intent;
        var row = ReadRow(transaction, intent.CommandId);
        if (row is not null)
        {
            var matching = row.Kind == intent.Kind && CryptographicOperations.FixedTimeEquals(row.RequestSha256, plan.RequestSha256) &&
                CenterRouting.SameFileCaller(row.Caller, intent.Caller);
            return (matching ? ApprovedFilePreparation.Existing : ApprovedFilePreparation.Conflict, plan);
        }
        if (!plan.Active) return (ApprovedFilePreparation.InvalidApproval, plan);
        if (plan.ApprovalExpiresAt <= sample.BoundaryMicroseconds)
            return (ApprovedFilePreparation.Expired, plan);
        if (transaction.Scalar("SELECT outcome FROM command_dedup WHERE command_id = $id;", ("$id", intent.CommandId)) is not null)
            return (ApprovedFilePreparation.Conflict, plan);
        if (HasTargetHold(transaction, intent.IdentityPlatform, intent.ParentIdentity, intent.TargetIdentity, intent.RelativePath, root))
            return (ApprovedFilePreparation.WorkspaceHeld, plan);
        cancellationToken.ThrowIfCancellationRequested();
        PrivateStageApproval.CheckTarget(intent, root, target, cancellationToken);
        PrivateStageApproval.CheckStage(intended, intent.IdentityPlatform, intent.IntendedStageIdentity,
            intent.IntendedSize, intent.IntendedSha256, cancellationToken);
        if (intent.TargetIdentity is null)
        {
            if (original is not null) throw new InvalidOperationException("An absent target has no original stage.");
        }
        else
        {
            if (original is null || target is null || intent.OriginalStageIdentity is null ||
                intent.OriginalSize is null || intent.OriginalSha256 is null)
                throw new InvalidOperationException("The approved preimage stage and target are required.");
            PrivateStageApproval.CheckStage(original, intent.IdentityPlatform, intent.OriginalStageIdentity,
                intent.OriginalSize.Value, intent.OriginalSha256, cancellationToken);
            if (original.ObjectIdentity.SameObject(intended.ObjectIdentity) ||
                original.ObjectIdentity.SameObject(target.ObjectIdentity) ||
                intended.ObjectIdentity.SameObject(target.ObjectIdentity))
                throw new WorkspacePathException("file_identity_changed");
        }
        // Recheck the target after hashing both stages and before recording a possible effect.
        PrivateStageApproval.CheckTarget(intent, root, target, cancellationToken);
        InsertApprovedIntent(transaction, plan);
        return (ApprovedFilePreparation.Prepared, plan);
    }

    // Caller has established either all guards for PREPARED or a verified pre-effect refusal.
    private static void InsertApprovedIntent(StoreTransaction transaction, PrivateStageApprovedPlan plan)
    {
        var intent = plan.Intent;
        var now = transaction.NowMicroseconds;
        transaction.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, target_identity, expected_absent,
               original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, $kind, 1, $digest, $caller, $correlation, $workspace, $path,
                    $platform, $root, $parent, $target, $absent, $original_size, $original_hash, $original_stage,
                    $intended_size, $intended_hash, $intended_stage, $now, $now, 1, 0);
            """,
            ("$id", intent.CommandId), ("$kind", (int)intent.Kind), ("$digest", plan.RequestSha256),
            ("$caller", intent.Caller.ToByteArray()), ("$correlation", intent.CorrelationId),
            ("$workspace", intent.WorkspaceId), ("$path", intent.RelativePath), ("$platform", intent.IdentityPlatform),
            ("$root", intent.RootIdentity), ("$parent", intent.ParentIdentity), ("$target", intent.TargetIdentity),
            ("$absent", intent.TargetIdentity is null ? 1 : 0), ("$original_size", intent.OriginalSize),
            ("$original_hash", intent.OriginalSha256), ("$original_stage", intent.OriginalStageIdentity),
            ("$intended_size", intent.IntendedSize), ("$intended_hash", intent.IntendedSha256),
            ("$intended_stage", intent.IntendedStageIdentity), ("$now", now));
    }

    /// <summary>
    /// Settles a verified result using the persisted approved digest and occurrence count. The caller must have actually
    /// completed the guarded target effect and durability checks; no file content or reserialized request is stored.
    /// </summary>
    internal static byte[] CompleteApprovedVerifiedEffect(StoreTransaction transaction, ReadOnlySpan<byte> approvalId,
        long resultingSize, ReadOnlySpan<byte> resultingSha256, uint? replacements)
    {
        RequireFull(transaction);
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId)
            ?? throw new InvalidOperationException("The approved file binding is unavailable.");
        var row = ReadRow(transaction, plan.Intent.CommandId)
            ?? throw new InvalidOperationException("The file journal is unavailable.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null ||
            !CryptographicOperations.FixedTimeEquals(row.RequestSha256, plan.RequestSha256) ||
            !CenterRouting.SameFileCaller(row.Caller, plan.Intent.Caller) ||
            resultingSize != row.IntendedSize || resultingSha256.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(row.IntendedSha256, resultingSha256) ||
            (row.Kind == FileOperationKind.Write ? replacements is not null :
                replacements is null or < 1 or > 1000 || replacements != plan.ExpectedOccurrences))
            throw new InvalidOperationException("The approved effect does not match the prepared file intent.");
        return CompleteCheckedEffect(transaction, row, resultingSize, resultingSha256, replacements);
    }

    /// <summary>
    /// Replays only an already settled outcome of the same captured approval, without reapplying the effect. A prepared
    /// entry has no outcome and must be resolved through interruption recovery rather than executed a second time.
    /// </summary>
    internal static byte[]? ReplayApproved(StoreReader reader, ReadOnlySpan<byte> approvalId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var plan = PrivateStageApprovedPlans.Read(reader, approvalId);
        if (plan is null) return null;
        var row = ReadRow(reader, plan.Intent.CommandId);
        if (row is null) return null;
        if (row.Kind != plan.Intent.Kind || !CryptographicOperations.FixedTimeEquals(row.RequestSha256, plan.RequestSha256) ||
            !CenterRouting.SameFileCaller(row.Caller, plan.Intent.Caller))
            throw new InvalidDataException("The approved command differs from its journal.");
        if (row.State == FileOperationState.Completed) _ = CompletedResult(row);
        else if (row.State == FileOperationState.Unknown) EnsureUnknownOutcome(row);
        else if (row.Outcome is not null) throw new InvalidDataException("A prepared file journal has an outcome.");
        return row.Outcome?.ToArray();
    }
}
