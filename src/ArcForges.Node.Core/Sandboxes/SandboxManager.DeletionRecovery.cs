// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal SandboxServiceDeleteResponse Delete(SandboxServiceDeleteRequest request, CancellationToken cancellationToken)
    {
        SandboxServiceDeleteResponse response;
        lock (OwnershipGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                response = DeleteLocked(request, cancellationToken);
            }
            catch (SandboxPrivateRootException failure)
            {
                return DeleteError(request.Meta, Error(request.Meta, ErrorCategory.Conflict, "identity_changed", failure.Reason));
            }
            catch (WorkspacePathException failure)
            {
                return DeleteError(request.Meta, Error(request.Meta, ErrorCategory.Validation, "path_rejected", failure.Reason));
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return DeleteError(request.Meta, StorageFailure(request.Meta));
            }
        }

        if (response.Value?.Operation?.State == OperationState.Accepted)
        {
            HoldRunFault("hold-delete-before-accepted-reply");
        }

        return response;
    }

    private SandboxServiceDeleteResponse DeleteLocked(SandboxServiceDeleteRequest request, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        if (meta is not { ExpectedNative: null, ExpectedRev.Value: > 0 and < long.MaxValue }
            || !ValidId(meta.CommandId) || !ValidId(request.OwnerEpoch) || !ValidId(request.SandboxId)
            || (request.PlanId is null) == (request.ResumeCommandId is null)
            || (request.PlanId is { } plan && !ValidId(plan))
            || (request.ResumeCommandId is { } resume && (!ValidId(resume) || resume.Value == meta.CommandId.Value))
            || !request.Equals(SandboxServiceDeleteRequest.Parser.WithDiscardUnknownFields(true).ParseFrom(request.ToByteArray())))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.Validation, "invalid_argument", "delete_shape_invalid"));
        }

        string sandboxId = ToHex(request.SandboxId);
        long expected = meta.ExpectedRev.Value;
        byte[] epoch = request.OwnerEpoch.Value.ToByteArray();
        byte[] commandId = meta.CommandId.Value.ToByteArray();
        var canonical = request.Clone();
        canonical.OwnerEpoch = null;
        canonical.Meta = null;
        var intent = new DurableIntent(commandId, epoch, SandboxDeletionRecords.Method, Aggregate, sandboxId,
            canonical.ToByteArray(), expected);
        var receipts = Receipts;
        if (!EpochMatches(request.OwnerEpoch) || receipts.Inspect(commandId) is not null)
        {
            return ResolveDeletion(receipts.Admit(intent), request, cancellationToken);
        }

        if (request.ResumeCommandId is not { } originalCommand)
        {
            return AdmitFreshDeletion(request, intent, cancellationToken);
        }

        var (sandbox, deletion) = _store.Read(reader => (SandboxRecords.Get(reader, OwnerId, sandboxId),
            SandboxDeletionRecords.ReadOriginal(reader, OwnerId, epoch, sandboxId, ToHex(originalCommand))));
        if (sandbox is null || deletion is null)
        {
            return DeleteError(meta, NotFound(meta));
        }

        if (sandbox.Revision != expected)
        {
            return DeleteError(meta, RevisionError(meta, expected, sandbox.Revision));
        }

        if (_deleteStopping || sandbox.State is not (StoredSandboxState.Deleting or StoredSandboxState.RecoveryRequired)
            || !ResumableDeletionPhase(deletion) || deletion.OriginalExpectedRevision <= 0
            || deletion.OriginalExpectedRevision >= expected
            || deletion.LatestSuccessorId is not null && (deletion.LatestExpectedRevision is not long previousRevision
                || previousRevision <= deletion.OriginalExpectedRevision || previousRevision >= expected
                || deletion.LatestSuccessorState is null))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.State, "busy", "deletion_phase_unconfirmed"));
        }

        if (sandbox.RootIdentity != deletion.RootIdentity || sandbox.RootRelative != SandboxPrivateRoots.RelativePath(sandboxId))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.Conflict, "identity_changed", "deletion_original_identity_changed"));
        }

        // An accepted successor holds the journal until its action is settled.
        if (deletion.LatestSuccessorState == "ACCEPTED" ||
            HasDeletionUse(sandboxId, epoch, deletion))
        {
            return DeleteError(meta, Error(meta, ErrorCategory.State, "managed_use", "sandbox_managed_use"));
        }

        RequireDeletionContinuation(sandbox, deletion);
        cancellationToken.ThrowIfCancellationRequested();
        intent = intent with { Deletion = new DurableDeletionBinding(deletion.OriginalCommandId, deletion.DeletionId) };
        var admission = receipts.Admit(intent, transaction =>
            RequireChanged(SandboxDeletionRecords.TryLinkSuccessor(transaction, sandbox, epoch, deletion, ToHex(meta.CommandId))));
        if (admission.Decision == DurableDecision.Execute)
        {
            ScheduleDeletion(sandboxId, epoch, deletion.OriginalCommandId);
        }

        return ResolveDeletion(admission, request, CancellationToken.None);
    }

    private static bool ResumableDeletionPhase(StoredSandboxDeletion deletion) => deletion.Phase switch
    {
        "locked" => deletion.QuarantineIdentity is null,
        "quarantined" or "removing" => deletion.QuarantineIdentity is not null,
        "recovery_required" => true,
        _ => false,
    };

    private SandboxServiceDeleteResponse ResolveDeletion(DurableAdmission admission, SandboxServiceDeleteRequest request,
        CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        switch (admission.Decision)
        {
            case DurableDecision.Conflict:
                return DeleteError(meta, Error(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed"));
            case DurableDecision.EpochRetired:
                return DeleteError(meta, Error(meta, ErrorCategory.Conflict, "owner_epoch_retired", "owner_epoch_mismatch"));
            case DurableDecision.RevisionConflict:
                return DeleteError(meta, Error(meta, ErrorCategory.Conflict, "revision_mismatch", "sandbox_revision_changed"));
            case DurableDecision.Capacity:
                return DeleteError(meta, Error(meta, ErrorCategory.Resource, "disk_space", "durable_receipt_capacity"));
            case DurableDecision.Maintenance:
                return DeleteError(meta, StorageFailure(meta));
            case DurableDecision.Compacted when admission.Receipt is { } compacted:
                var error = Error(meta, ErrorCategory.State, "receipt_compacted", "original_response_compacted",
                    (EffectCertainty)compacted.Effect);
                error.Details.State.State = compacted.State;
                error.Details.State.Resource = AggregateIdentity(compacted);
                error.Retry.ReconciliationOperation = "NodeService.GetOperation";
                return DeleteError(meta, error);
        }

        var observed = GetOperation(new()
        {
            Meta = meta,
            OwnerEpoch = request.OwnerEpoch,
            CommandId = meta.CommandId,
        }, cancellationToken);
        if (observed.Error is { } refused)
        {
            return DeleteError(meta, refused);
        }

        var operation = observed.Value.Operation;
        if (operation.State == OperationState.Accepted)
        {
            operation.Revision ??= new Revision { Value = checked(meta.ExpectedRev.Value + 1) };
        }

        return new() { Meta = Response(meta, operation.Revision?.Value), Value = new() { Operation = operation } };
    }

    private static SandboxServiceDeleteResponse DeleteError(RequestMeta? meta, ArcError error) =>
        new() { Meta = Response(meta), Error = error };
}
