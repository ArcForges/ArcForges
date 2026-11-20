// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private DataMutation CloseDataEffect(RequestMeta meta, StoredTransfer row, DurableIntent intent,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (row.ClosedAt is not null)
        {
            lock (OwnershipGate)
            {
                return ResolveDataAdmission(meta, Receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened,
                    DataReceiptBody(row)));
            }
        }

        var pending = NextDataRow(row, new(StoredTransferPhase.Close, Convert.ToHexStringLower(intent.CommandId),
            TargetIdentity: row.StagingIdentity));
        var admission = AdmitDataStep(intent, row, pending);
        if (admission.Decision != DurableDecision.Execute)
        {
            return ResolveDataAdmission(meta, admission);
        }

        try
        {
            ReleaseDataStage(pending);
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            return SettleDataUnknown(meta, intent, pending, DataError(meta, failure));
        }

        var closed = ClosedDataRow(pending, StoredTransferCloseReason.ExplicitClose);
        return new(closed, SettleData(intent.CommandId, pending, closed, "SUCCEEDED", EffectCertainty.Happened), null);
    }

    private void ReleaseDataStage(StoredTransfer row)
    {
        if (row.State == StoredTransferState.Failed
            || (row.Direction == StoredTransferDirection.Import && row.State == StoredTransferState.Complete))
        {
            // A known failed Begin already released its stage; a verified import consumed its own stage in publication.
            return;
        }

        if (row.StagingIdentity == TransferRecords.UnboundStage)
        {
            throw new DataEffectException(ErrorCategory.Execution, "outcome_unknown", "transfer_stage_identity_unbound");
        }

        using var staging = OpenDataStaging(row);
        staging.RemoveSandboxDataStage(row.TransferId, row.StagingIdentity, static () => { });
    }

    private StoredTransfer ClosedDataRow(StoredTransfer row, StoredTransferCloseReason reason) =>
        NextDataRow(row, null) with
        {
            State = row.State == StoredTransferState.Complete ? row.State : StoredTransferState.Failed,
            Effect = row.State == StoredTransferState.Complete ? (int)EffectCertainty.Happened : (int)EffectCertainty.DidNotHappen,
            ClosedAt = _clock.GetUtcNow(),
            CloseReason = reason,
        };
}
