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
    // A bounded set of lanes prevents two local decisions/resume attempts from executing the same approval at once.
    private readonly SemaphoreSlim[] _approvalLanes = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    /// <summary>
    /// Executes only a content-free reference created by the file approval producer. The local approval service
    /// supplies the approved original caller; this method never treats the old routed signature as a live channel.
    /// </summary>
    internal async Task<byte[]?> ExecuteApprovedReferenceAsync(byte[] reference, Caller caller)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(caller);
        if (reference.Length != 17 || reference[0] != 1 || caller.ApprovalId is not { Length: 16 } approvalId ||
            caller.CenterCaller is null || caller.RemoteCommandId?.Value.Span.SequenceEqual(reference.AsSpan(1)) != true ||
            !caller.Approved || caller.Routed is not null)
            return null;

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), node.Clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, node.Stopping);
        var token = linked.Token;
        var lane = _approvalLanes[reference[1] % _approvalLanes.Length];
        try { await lane.WaitAsync(token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return null; }
        using var lease = new ApprovedMutationLease();
        try
        {
            var start = await node.Processor.ExecuteAsync(command =>
                BeginApproved(command.Transaction, approvalId, reference, caller, lease, token), CommitDurability.Full).ConfigureAwait(false);
            if (!start.Ready) return start.Outcome;
            // Never dispose a held target or stage while this callback may still be doing native I/O.
            return await node.Processor.ExecuteAsync(command =>
                ApplyApproved(command.Transaction, approvalId, caller, lease, token), CommitDurability.Full).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // PREPARED, if committed, stays held and recovery resolves it as UNKNOWN. A failed transaction is not proof
            // that its target effect did or did not happen. The approval remains APPROVED for a later safe recovery.
            node.Log.Error("api.file.approval.execution_deferred");
            return null;
        }
        finally
        {
            lane.Release();
        }
    }

    private ApprovedMutationStart BeginApproved(StoreTransaction transaction, byte[] approvalId, byte[] reference,
        Caller caller, ApprovedMutationLease lease, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var plan = PrivateStageApprovedPlans.Read(transaction, approvalId);
        if (plan is null || !plan.Intent.CommandId.AsSpan().SequenceEqual(reference.AsSpan(1)) ||
            !CenterRouting.SameFileCaller(plan.Intent.Caller, caller.CenterCaller))
            return new ApprovedMutationStart(false);

        // A previously PREPARED effect is never repeated, even if its reply or approval settlement was lost.
        if (FileMutationJournal.GetForCaller(transaction, plan.Intent.CommandId, plan.Intent.Caller) is not null)
            return new ApprovedMutationStart(false, FileMutationJournal.ReplayApproved(transaction, approvalId));

        var sample = RoutedFileValidationTime.Advance(transaction);
        if (!sample.Healthy) return new ApprovedMutationStart(false);
        if (sample.BoundaryMicroseconds >= plan.ApprovalExpiresAt)
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.ApprovalExpired));
        if (!ApprovedWriteAllowed(transaction, caller, plan))
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.PolicyDenied));
        if (!OperatingSystem.IsWindows())
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.EnforcementUnavailable));
        try
        {
            lease.Use = _workspaces.OpenForUse(transaction, plan.Intent.WorkspaceId,
                beforeUse: tx =>
                {
                    if (!ApprovedWriteAllowed(tx, caller, plan)) throw new FilePolicyException("denied");
                }, token);
            if (plan.Intent.TargetIdentity is not null)
            {
                lease.Target = lease.Use.Root.OpenExistingWriteGuard(plan.Intent.RelativePath);
                lease.Original = PrivateStageRegistry.ReopenReadyStage(transaction, plan.Intent.CommandId, 1,
                    plan.Intent.Caller, plan.RequestSha256, token);
            }
            else
            {
                var slash = plan.Intent.RelativePath.LastIndexOf('/');
                lease.ParentIdentity = WorkspacePath.Identity(lease.Use.Root.OpenDirectory(
                    slash < 0 ? "" : plan.Intent.RelativePath[..slash]));
            }
            lease.Intended = PrivateStageRegistry.ReopenReadyStage(transaction, plan.Intent.CommandId, 2,
                plan.Intent.Caller, plan.RequestSha256, token);
            var prepared = FileMutationJournal.PrepareApproved(transaction, approvalId, lease.Use.Root, lease.Target,
                lease.Original, lease.Intended, token);
            return prepared.Status switch
            {
                ApprovedFilePreparation.Prepared => new ApprovedMutationStart(true),
                ApprovedFilePreparation.Existing => new ApprovedMutationStart(false, FileMutationJournal.ReplayApproved(transaction, approvalId)),
                ApprovedFilePreparation.Expired => new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(
                    transaction, approvalId, ApprovedFileRefusal.ApprovalExpired)),
                _ => new ApprovedMutationStart(false),
            };
        }
        catch (FilePolicyException)
        {
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.PolicyDenied));
        }
        catch (WorkspacePathException exception) when (exception.Reason is "file_identity_changed" or "directory_identity_changed" or
            "root_changed" or "hash_mismatch")
        {
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.TargetChanged));
        }
        catch (RegisteredWorkspaceException exception) when (exception.Reason == "workspace_root_changed")
        {
            return new ApprovedMutationStart(false, FileMutationJournal.RecordApprovedPreEffectRefusal(transaction,
                approvalId, ApprovedFileRefusal.TargetChanged));
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
        }

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
                return FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, created.Size, created.Sha256, replacements: null);
            }
            catch (Exception failure) when (failure is not OutOfMemoryException and not StackOverflowException)
            {
                // Exclusive creation itself was an effect, even when no file-content write began.
                return FileMutationJournal.MarkUnknown(transaction, plan.Intent.CommandId);
            }
        }

        try
        {
            var result = lease.Use!.Root.ApplyExistingGuardedStage(plan.Intent.RelativePath, lease.Target!, lease.Intended!,
                plan.Intent.OriginalSha256!, afterFirstEffect: null, beforeEachEffect: BeforeEffect, token);
            return FileMutationJournal.CompleteApprovedVerifiedEffect(transaction, approvalId, result.Size, result.Sha256,
                plan.Intent.Kind == FileOperationKind.Edit ? plan.ExpectedOccurrences : null);
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

    private sealed record ApprovedMutationStart(bool Ready, byte[]? Outcome = null);

    private sealed class ApprovedFileExpiredException : Exception;

    private sealed class ApprovedMutationLease : IDisposable
    {
        internal RegisteredWorkspaceUse? Use { get; set; }
        internal WorkspaceWriteGuard? Target { get; set; }
        internal WorkspaceCreatedTarget? Created { get; set; }
        internal WorkspaceObjectIdentity? ParentIdentity { get; set; }
        internal RecoveredPrivateStage? Original { get; set; }
        internal RecoveredPrivateStage? Intended { get; set; }

        public void Dispose()
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
