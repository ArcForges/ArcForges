// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int DeletePreviewLimit = 64;
    private const int DeletePreviewBlockerLimit = 512;
    private static readonly TimeSpan DeletePreviewLifetime = TimeSpan.FromMinutes(5);

    // A preview is scoped to this process. The first accepted use is durable in deletion_journal.
    private readonly Dictionary<string, SandboxDeletePreview> _deletePreviews = new(StringComparer.Ordinal);

    private sealed record SandboxDeletePreview(string SandboxId, long Revision, string RootIdentity, long RootGeneration,
        byte[] OwnerEpoch, DateTimeOffset ExpiresAt);

    internal SandboxServicePlanDeleteResponse PlanDelete(SandboxServicePlanDeleteRequest request, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        if (!ValidId(request.SandboxId))
        {
            return Failure(Error(meta, ErrorCategory.Validation, "invalid_argument", "delete_plan_shape_invalid"));
        }

        var id = ToHex(request.SandboxId);
        try
        {
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, id));
                if (row is null || row.State == StoredSandboxState.Deleted)
                {
                    return Failure(NotFound(meta));
                }

                if (row.State is not (StoredSandboxState.Ready or StoredSandboxState.Error))
                {
                    return Failure(Error(meta, ErrorCategory.State, "busy", "fresh_deletion_state_invalid"));
                }

                using var root = _roots.Inspect(id, row.RootIdentity);
                var now = _clock.GetUtcNow();
                foreach (var expired in _deletePreviews.Where(item => item.Value.ExpiresAt <= now).Select(item => item.Key).ToArray())
                {
                    _deletePreviews.Remove(expired);
                }

                if (_deletePreviews.Count >= DeletePreviewLimit)
                {
                    return Failure(Error(meta, ErrorCategory.Resource, "budget_unavailable", "delete_preview_capacity"));
                }

                var blockerIds = _store.Read(reader =>
                {
                    var runs = SandboxRecords.ListDeletionBlockingRuns(reader, OwnerId, id, DeletePreviewBlockerLimit + 1);
                    var releasing = _liveRuns.Keys.Where(runId => RunRecords.Get(reader, OwnerId, runId)?.SandboxId == id);
                    var transfers = SandboxRecords.ListDeletionBlockingTransfers(reader, OwnerId, id, DeletePreviewBlockerLimit + 1);
                    return (Runs: runs.Concat(releasing).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(), Transfers: transfers);
                });
                if (blockerIds.Runs.Length > DeletePreviewBlockerLimit || blockerIds.Transfers.Count > DeletePreviewBlockerLimit)
                {
                    return Failure(Error(meta, ErrorCategory.State, "managed_use", "delete_preview_managed_use_limit"));
                }

                var planId = Guid.NewGuid().ToString("N");
                var expiry = now + DeletePreviewLifetime;
                var plan = new DeletePlan
                {
                    PlanId = FromHex(planId),
                    SandboxId = request.SandboxId.Clone(),
                    Revision = new Revision { Value = row.Revision },
                    RootIdentityDigest = Hash(row.RootIdentity),
                    ExpiresAt = ProtoTime.ToInstant(expiry),
                };
                if (ObservedSandboxOwnedBytes(row) is { } bytes)
                {
                    plan.OwnedBytes = bytes;
                }

                plan.ExcludedHostGrants.AddRange(FromStored(row.Config).HostGrants.Select(grant => grant.HostPath));
                plan.BlockingRuns.AddRange(blockerIds.Runs.Select(FromHex));
                plan.BlockingTransferIds.AddRange(blockerIds.Transfers.Select(FromHex));
                _deletePreviews.Add(planId, new SandboxDeletePreview(id, row.Revision, row.RootIdentity, row.RootGeneration,
                    Receipts.OwnerEpoch.ToArray(), expiry));
                return new SandboxServicePlanDeleteResponse
                {
                    Meta = Response(meta, row.Revision),
                    Value = new SandboxServicePlanDeleteValue { Plan = plan },
                };
            }
        }
        catch (SandboxPrivateRootException failure)
        {
            return Failure(Error(meta, ErrorCategory.Conflict, "identity_changed", failure.Reason));
        }
        catch (WorkspacePathException failure)
        {
            return Failure(Error(meta, ErrorCategory.Validation, "path_rejected", failure.Reason));
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return Failure(StorageFailure(meta));
        }

        SandboxServicePlanDeleteResponse Failure(ArcError error) => new() { Meta = Response(meta), Error = error };
    }
}
