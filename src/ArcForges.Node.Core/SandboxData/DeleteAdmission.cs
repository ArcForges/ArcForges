// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private SandboxServiceDeleteResponse AdmitFreshDeletion(SandboxServiceDeleteRequest request, DurableIntent intent,
        CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        var sandboxId = ToHex(request.SandboxId);
        var planId = ToHex(request.PlanId);
        var epoch = intent.OwnerEpoch;
        var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId));
        if (row is null || row.State == StoredSandboxState.Deleted)
        {
            return DeleteError(meta, NotFound(meta));
        }

        if (row.Revision != meta.ExpectedRev.Value)
        {
            return DeleteError(meta, RevisionError(meta, meta.ExpectedRev.Value, row.Revision));
        }

        if (_deleteStopping || row.State is not (StoredSandboxState.Ready or StoredSandboxState.Error))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.State, "busy", "fresh_deletion_state_invalid"));
        }

        if (!_deletePreviews.TryGetValue(planId, out var preview) || preview.ExpiresAt <= _clock.GetUtcNow()
            || preview.SandboxId != sandboxId || !preview.OwnerEpoch.AsSpan().SequenceEqual(epoch))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.State, "busy", "delete_preview_unavailable"));
        }

        if (preview.Revision != row.Revision || preview.RootIdentity != row.RootIdentity || preview.RootGeneration != row.RootGeneration
            || row.RootRelative != SandboxPrivateRoots.RelativePath(sandboxId))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.Conflict, "identity_changed", "delete_preview_identity_changed"));
        }

        if (HasDeletionUse(sandboxId, epoch))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.State, "managed_use", "sandbox_managed_use"));
        }

        _deletionEffects.RequireFreshDeletion(sandboxId, row.RootIdentity);
        cancellationToken.ThrowIfCancellationRequested();
        var command = ToHex(meta.CommandId);
        var detached = DetachDeletionGrants(row.Config);
        var admission = Receipts.Admit(intent, transaction =>
            RequireChanged(SandboxDeletionRecords.TryAdmitFresh(transaction, row, epoch, planId, command, detached)));
        if (admission.Decision == DurableDecision.Execute)
        {
            _deletePreviews.Remove(planId);
            ScheduleDeletion(sandboxId, epoch, command);
        }

        return ResolveDeletion(admission, request, CancellationToken.None);
    }

    private static StoredSandboxConfig DetachDeletionGrants(StoredSandboxConfig stored)
    {
        var config = FromStored(stored);
        if (config.HostGrants.Count == 0)
        {
            return stored;
        }

        config.HostGrants.Clear();
        return ToStored(config);
    }

    private bool HasDeletionUse(string sandboxId, byte[] epoch, StoredSandboxDeletion? continuation = null) =>
        _deletionWorkers.ContainsKey(sandboxId) || HasSandboxDataReaders(sandboxId) ||
        _store.Read(reader =>
            SandboxRecords.HasUnresolvedUse(reader, OwnerId, sandboxId, epoch, continuation: continuation)
            || _liveRuns.Keys.Any(runId => RunRecords.Get(reader, OwnerId, runId)?.SandboxId == sandboxId));

    private void RequireDeletionContinuation(StoredSandbox row, StoredSandboxDeletion journal)
    {
        if (journal is { RemovalVerified: true, QuarantineIdentity: { } removed })
        {
            _deletionEffects.VerifyRecordedRemoval(row.SandboxId, journal.RootIdentity, journal.DeletionId, removed);
            return;
        }

        try
        {
            _deletionEffects.RequireDeletionContinuation(row.SandboxId, journal.RootIdentity, journal.DeletionId, journal.QuarantineIdentity);
        }
        catch (SandboxPrivateRootException failure) when (journal.QuarantineIdentity is null &&
            (IsMissingDeletionSource(failure) || failure.Reason == "deletion_quarantine_location_occupied"))
        {
            // A prior attempt may have moved the exact root before the quarantine identity was committed.
            try
            {
                _ = _deletionEffects.ObserveQuarantinedDeletion(row.SandboxId, journal.RootIdentity, journal.DeletionId);
            }
            catch (WorkspacePathException missing) when (IsMissingDeletionSource(missing))
            {
                throw new SandboxPrivateRootException(missing.Reason, inner: missing);
            }
        }
    }
}
