// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private byte[]? RegisterApprovedLinuxWorker(StoreTransaction transaction, byte[] approvalId, byte[] commandId,
        Caller caller, ApprovedMutationLease lease, long nativeDeadline, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        token.ThrowIfCancellationRequested();
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId)
            ?? throw new InvalidOperationException("The approved caller binding is unavailable.");
        var beforeSample = LinuxFatalDeadline.MonotonicNanoseconds();
        var time = RoutedFileValidationTime.Advance(transaction);
        if (!time.Healthy) throw new InvalidOperationException("The validation boundary is unavailable.");
        if (time.BoundaryMicroseconds >= plan.ApprovalExpiresAt)
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.ApprovalExpired);
        if (!ApprovedWriteAllowed(transaction, caller, plan))
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.PolicyDenied);
        var bounded = Math.Min(nativeDeadline, checked(beforeSample + (plan.ApprovalExpiresAt - time.BoundaryMicroseconds) * 1000));
        if (beforeSample >= bounded) throw new OperationCanceledException(token);
        lease.CheckNames?.Invoke();
        lease.CreationSelection?.CheckNames(null);
        plan = FileEffectWorker.RecordApprovedChild(transaction, approvalId, commandId, caller.CenterCaller!, lease.Worker!.SealedWorker);
        lease.NativeDeadline = bounded;
        if (plan.Intent.TargetIdentity is null)
            lease.LinuxCreation = LinuxFileCreationBinding.FromApproved(plan, bounded, plan.ApprovalExpiresAt);
        else lease.LinuxBinding = LinuxFileEffectBinding.FromApproved(plan, bounded, plan.ApprovalExpiresAt);
        return null;
    }

    private byte[]? ApplyApprovedLinux(StoreTransaction transaction, byte[] approvalId, Caller caller,
        ApprovedMutationLease lease, PrivateStageApprovedPlan plan, Action beforeEffect, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var worker = lease.Worker ?? throw new InvalidOperationException("The exact approved effect child is unavailable.");
        try
        {
            beforeEffect();
            if (plan.Intent.TargetIdentity is null)
            {
                var result = worker.ExecuteCreation(lease.LinuxCreation!, lease.Use!.Root, plan.Intent.RelativePath,
                    lease.CreationSelection!, lease.Intended!, beforeEffect, BeforeCreateForTests, AfterCreateForTests, token);
                lease.Created = result.Target;
                lease.WorkerEnded = FileEffectWorker.MarkEndedIfObserved(transaction, plan.Intent.CommandId);
                if (!lease.WorkerEnded)
                    return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
                beforeEffect();
                result.Target.Guard.CheckIntact();
                var outcome = FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, result.Content.Size,
                    result.Content.Sha256, replacements: null, result.Ownership);
                result.Target.Guard.CheckIntact();
                return outcome;
            }
            var ownership = FileCreationOwnership.PrepareUpdate(transaction, plan.Intent.Caller, plan.Intent.WorkspaceId,
                lease.Use!.Root, plan.Intent.RelativePath, lease.Target!, plan.Intent.OriginalSha256!, token);
            beforeEffect();
            var mutation = worker.Execute(lease.LinuxBinding!, lease.Use.Root, lease.Target!, lease.Original!, lease.Intended!,
                beforeEffect, lease.CheckNames!, token);
            lease.Target = mutation.Guard;
            lease.WorkerEnded = FileEffectWorker.MarkEndedIfObserved(transaction, plan.Intent.CommandId);
            if (!lease.WorkerEnded)
                return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
            beforeEffect();
            if (ownership is not null && !FileCreationOwnership.ConfirmUpdate(ownership, lease.Use.Root, mutation.Guard,
                mutation.Content.Size, mutation.Content.Sha256, token)) ownership = null;
            var completed = FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, mutation.Content.Size,
                mutation.Content.Sha256, plan.Intent.Kind == FileOperationKind.Edit ? plan.ExpectedOccurrences : null,
                ownershipUpdate: ownership);
            mutation.Guard.CheckIntact();
            return completed;
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            worker.Stop();
            if (worker.WaitForActualExit(2000) && FileEffectWorker.MarkEndedIfObserved(transaction, plan.Intent.CommandId))
            {
                lease.WorkerEnded = true;
                // EEXIST is a native, exact-parent no-create result, including the case where G had been sent.
                if (failure is WorkspaceCreateCollisionException collision)
                    return FileMutationJournal.CompleteApprovedAbsentConflict(transaction, approvalId, collision);
                if (!worker.PossibleEffect)
                {
                    var refusal = failure switch
                    {
                        FilePolicyException => ApprovedFileRefusal.PolicyDenied,
                        ApprovedFileExpiredException => ApprovedFileRefusal.ApprovalExpired,
                        WorkspacePathException native when native.Reason is "hash_mismatch" or "file_identity_changed" or
                            "directory_identity_changed" or "parent_identity_changed" or "root_changed" => ApprovedFileRefusal.TargetChanged,
                        _ => ApprovedFileRefusal.EnforcementUnavailable,
                    };
                    return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, refusal);
                }
            }
            // Any granted target permission or unproved actual exit retains UNKNOWN and the durable target hold.
            return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
        }
    }
}
