// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Scheduling;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Policy;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    /// <summary>Replays only a settled, bound legacy approval result. An unfinished approval stays deferred.</summary>
    internal Task<byte[]?> ExecuteApprovedReferenceAsync(byte[] reference, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(caller);
        if (reference.Length != 17 || reference[0] != 1 || caller.ApprovalId is not { Length: 16 } approvalId ||
            caller.CenterCaller is null || caller.RemoteCommandId?.Value.Span.SequenceEqual(reference.AsSpan(1)) != true ||
            !caller.Approved || caller.Routed is not null || node.Stopping.IsCancellationRequested)
            return Task.FromResult<byte[]?>(null);

        try
        {
            return Task.FromResult(node.Store.Read<byte[]?>(reader =>
            {
                if (node.Stopping.IsCancellationRequested)
                    return null;
                var plan = PrivateStageApprovedPlans.Read(reader, approvalId);
                if (plan is null || !plan.Intent.CommandId.AsSpan().SequenceEqual(reference.AsSpan(1)) ||
                    !CenterRouting.SameFileCaller(plan.Intent.Caller, caller.CenterCaller))
                    return null;

                return FileMutationJournal.GetForCaller(reader, plan.Intent.CommandId, plan.Intent.Caller)
                    is { State: FileOperationState.Completed }
                    ? FileMutationJournal.ReplayApproved(reader, approvalId)
                    : null;
            }));
        }
        catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
        {
            node.Log.Error("api.file.approval.execution_deferred");
            return Task.FromResult<byte[]?>(null);
        }
    }

    private byte[]? ApplyApproved(StoreTransaction transaction, byte[] approvalId, Caller caller,
        ApprovedMutationLease lease, CancellationToken token)
    {
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId);
        if (plan is null) return null;
        var sample = RoutedFileValidationTime.Advance(transaction);
        if (!sample.Healthy) return null;
        if (sample.BoundaryMicroseconds >= plan.ApprovalExpiresAt)
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.ApprovalExpired);
        if (!ApprovedWriteAllowed(transaction, caller, plan))
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.PolicyDenied);

        void BeforeEffect()
        {
            token.ThrowIfCancellationRequested();
            var time = RoutedFileValidationTime.Sample(transaction);
            if (!time.Healthy) throw new InvalidOperationException("File validation time is unavailable.");
            if (time.BoundaryMicroseconds >= plan.ApprovalExpiresAt) throw new ApprovedFileExpiredException();
            if (!ApprovedWriteAllowed(transaction, caller, plan)) throw new FilePolicyException("denied");
            if (OperatingSystem.IsLinux() && LinuxFatalDeadline.MonotonicNanoseconds() >= lease.NativeDeadline)
                throw new OperationCanceledException(token);
        }

        if (OperatingSystem.IsLinux()) return ApplyApprovedLinux(transaction, approvalId, caller, lease, plan, BeforeEffect, token);

        if (plan.Intent.TargetIdentity is null)
        {
            try
            {
                lease.Created = lease.Use!.Root.CreateWindowsNewTarget(plan.Intent.RelativePath, lease.ParentIdentity!.Value,
                    lease.Intended!, BeforeCreateForTests, BeforeEffect, token);
            }
            catch (WorkspaceCreateCollisionException collision)
            {
                return FileMutationJournal.CompleteApprovedAbsentConflict(transaction, approvalId, collision);
            }
            catch (WorkspaceCreateUncertainException)
            {
                return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
            }
            catch (FilePolicyException)
            {
                return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.PolicyDenied);
            }
            catch (ApprovedFileExpiredException)
            {
                return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.ApprovalExpired);
            }
            catch (WorkspacePathException failure) when (failure.Reason is "parent_identity_changed" or "directory_identity_changed" or
                "root_changed" or "file_identity_changed")
            {
                return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.TargetChanged);
            }

            try
            {
                AfterCreateForTests?.Invoke();
                var created = lease.Use!.Root.ApplyExistingGuardedStage(plan.Intent.RelativePath, lease.Created.Guard,
                    lease.Intended!, SHA256.HashData(ReadOnlySpan<byte>.Empty), afterFirstEffect: null, beforeEachEffect: BeforeEffect, token);
                var ownership = lease.Use.Root.MarkCreatedTarget(plan.Intent.RelativePath, lease.Created, created.Size, created.Sha256,
                    BeforeEffect, token);
                return FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, created.Size, created.Sha256,
                    replacements: null, ownership);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
            {
                // Exclusive creation itself was an effect, even when no file-content write began.
                return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
            }
        }

        try
        {
            var ownership = FileCreationOwnership.PrepareUpdate(transaction, plan.Intent.Caller, plan.Intent.WorkspaceId,
                lease.Use!.Root, plan.Intent.RelativePath, lease.Target!, plan.Intent.OriginalSha256!, token);
            var result = lease.Use.Root.ApplyExistingGuardedStage(plan.Intent.RelativePath, lease.Target!, lease.Intended!,
                plan.Intent.OriginalSha256!, afterFirstEffect: null, beforeEachEffect: BeforeEffect, token);
            if (ownership is not null && !FileCreationOwnership.ConfirmUpdate(ownership, lease.Use.Root, lease.Target!,
                result.Size, result.Sha256, token)) ownership = null;
            return FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, result.Size, result.Sha256,
                plan.Intent.Kind == FileOperationKind.Edit ? plan.ExpectedOccurrences : null, ownershipUpdate: ownership);
        }
        catch (WorkspaceGuardedMutationException exception) when (exception.PossibleEffect)
        {
            return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
        }
        catch (WorkspaceGuardedMutationException exception) when (exception.InnerException is FilePolicyException)
        {
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.PolicyDenied);
        }
        catch (WorkspaceGuardedMutationException exception) when (exception.InnerException is ApprovedFileExpiredException)
        {
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.ApprovalExpired);
        }
        catch (WorkspaceGuardedMutationException exception) when (exception.InnerException is WorkspacePathException native &&
            native.Reason is "file_identity_changed" or "directory_identity_changed" or "root_changed" or "hash_mismatch")
        {
            return FileMutationJournal.CompleteApprovedPreparedRefusal(transaction, approvalId, ApprovedFileRefusal.TargetChanged);
        }
    }

    private bool ApprovedWriteAllowed(StoreReader reader, Caller caller, PrivateStageApprovedPlan plan)
    {
        if (!caller.Approved || caller.CenterCaller is not { } center ||
            !CenterRouting.SameFileCaller(plan.Intent.Caller, center)) return false;
        try
        {
            var policy = PolicyRules.Current(reader);
            if (!CryptographicOperations.FixedTimeEquals(policy.Digest, PolicyDocuments.Digest(policy.Document)) ||
                policy.Document.Permissions.Any(item => PermissionMatrix.Valid(item) is not null) ||
                policy.Document.CenterRouted is { HasRelayedFrom: true } route &&
                route.RelayedFrom is not (RelayedFrom.Unspecified or RelayedFrom.OwnNode or RelayedFrom.Account) ||
                CenterRouting.Refusal(center, node.NodeId.Span, policy.Document.CenterRouted) is not null)
                return false;
            var decision = PermissionMatrix.DecideRouted(PermissionMatrix.FileWrite, caller.CellsOrigin, policy.Document.Permissions).Decision;
            return decision == PermissionDecision.Allow || decision == PermissionDecision.Approval && caller.CellsOrigin != Origin.Agent;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            return false;
        }
    }

    private sealed class ApprovedFileExpiredException : Exception;

    private sealed class ApprovedMutationLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use { get; set; }
        internal WorkspaceWriteGuard? Target { get; set; }
        internal WorkspaceCreatedTarget? Created { get; set; }
        internal WorkspaceObjectIdentity? ParentIdentity { get; set; }
        internal RecoveredPrivateStage? Original { get; set; }
        internal RecoveredPrivateStage? Intended { get; set; }
        internal LinuxFileEffectController? Worker { get; set; }
        internal LinuxFileEffectBinding? LinuxBinding { get; set; }
        internal LinuxFileCreationBinding? LinuxCreation { get; set; }
        internal WorkspaceLinuxCreationSelection? CreationSelection { get; set; }
        internal Action? CheckNames { get; set; }
        internal long NativeDeadline { get; set; }
        internal bool WorkerEnded { get; set; }

        public void Dispose()
        {
            if (OperatingSystem.IsLinux() && Worker is { } worker)
            {
                Worker = null;
                if (WorkerEnded)
                {
                    // The FULL effect callback has independently observed the exact original generation ended.
                    // Release our target guard before a completed RPC becomes visible to the next operation.
                    worker.Shutdown(afterExit: null);
                    DisposeObjects();
                }
                else worker.Shutdown(DisposeObjects);
            }
            else DisposeObjects();
        }

        private void DisposeObjects()
        {
            try { Intended?.Dispose(); }
            finally
            {
                try { Original?.Dispose(); }
                finally
                {
                    try { Target?.Dispose(); }
                    finally
                    {
                        try { Created?.Dispose(); }
                        finally { Use?.Dispose(); }
                    }
                }
            }
        }
    }
}
