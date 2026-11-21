// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Sandboxes;

/// <summary>The guarded native effects used by the durable Sandbox deletion workflow.</summary>
internal interface ISandboxDeletionEffects
{
    void RequireFreshDeletion(string sandboxId, string originalIdentity);

    void RequireDeletionContinuation(string sandboxId, string originalIdentity, string deletionId, string? quarantineIdentity);

    string QuarantineDeletion(string sandboxId, string originalIdentity, string deletionId, Action applied,
        CancellationToken cancellationToken);

    string ObserveQuarantinedDeletion(string sandboxId, string originalIdentity, string deletionId);

    void VerifyRecordedRemoval(string sandboxId, string originalIdentity, string deletionId, string quarantineIdentity);

    SandboxRemovalBatchResult RemoveDeletionBatch(string sandboxId, string originalIdentity, string deletionId,
        string quarantineIdentity, int maximumEntries, Action applied, CancellationToken cancellationToken);
}
