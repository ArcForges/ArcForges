// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int DeleteBatchSize = 128;
    private const int DeleteBatchLimit = 16;
    private static readonly TimeSpan DeletePassLimit = TimeSpan.FromSeconds(8);
    private readonly Dictionary<string, Task> _deletionWorkers = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _deleteStop = new();
    private bool _deleteStopping;

    private void ScheduleDeletion(string sandboxId, byte[] epoch, string originalCommand)
    {
        _deletionWorkers.Add(sandboxId, Task.Run(() => ExecuteDeletion(sandboxId, epoch, originalCommand), CancellationToken.None));
    }

    internal void ReconcileDeletionReceipts()
    {
        lock (OwnershipGate)
        {
            var pending = _store.Read(reader => SandboxDeletionRecords.ReadPending(reader, OwnerId));
            foreach (var item in pending)
            {
                if (item.Journal.OriginalState == "ACCEPTED" || item.Journal.LatestSuccessorState == "ACCEPTED")
                {
                    RecordDeleteUncertainty(item.SandboxId, item.OwnerEpoch, item.Journal.OriginalCommandId,
                        "deletion_worker_interrupted", recoveryRequired: true);
                }
            }
        }
    }

    internal void StopDeletionWorkers()
    {
        Task[] workers;
        lock (OwnershipGate)
        {
            _deleteStopping = true;
            _deleteStop.Cancel();
            workers = [.. _deletionWorkers.Values];
        }

        Task.WhenAll(workers).GetAwaiter().GetResult();
    }

    private void ExecuteDeletion(string sandboxId, byte[] epoch, string originalCommand)
    {
        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(_deleteStop.Token);
            budget.CancelAfter(DeletePassLimit);
            HoldRunFault("hold-delete-after-lock");
            var work = GetDeletionWork(sandboxId, epoch, originalCommand);
            var quarantine = work.Journal.QuarantineIdentity;
            if (work.Journal.RemovalVerified && quarantine is not null)
            {
                _roots.VerifyRecordedRemoval(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId, quarantine);
                CompleteDeletion(work, epoch);
                return;
            }

            if (quarantine is null)
            {
                var moved = false;
                try
                {
                    budget.Token.ThrowIfCancellationRequested();
                    quarantine = _roots.QuarantineDeletion(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId,
                        () => moved = true, budget.Token);
                }
                catch (Exception failure) when (!moved && IsMissingDeletionSource(failure))
                {
                    quarantine = _roots.ObserveQuarantinedDeletion(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId);
                }

                AdvanceDeletion(work, epoch, "quarantined", quarantine);
                HoldRunFault("hold-delete-after-quarantine");
                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            if (work.Journal.Phase != "removing")
            {
                AdvanceDeletion(work, epoch, "removing", quarantine);
                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            for (var index = 0; index < DeleteBatchLimit; index++)
            {
                budget.Token.ThrowIfCancellationRequested();
                var batch = _roots.RemoveDeletionBatch(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId,
                    quarantine, DeleteBatchSize, () => HoldRunFault("hold-delete-during-removal"), budget.Token);
                if (batch.RootAbsent)
                {
                    HoldRunFault("hold-delete-before-removal-proof");
                    _roots.VerifyRecordedRemoval(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId, quarantine);
                    RecordDeletionRemoval(work, epoch);
                    HoldRunFault("hold-delete-before-tombstone");
                    CompleteDeletion(GetDeletionWork(sandboxId, epoch, originalCommand), epoch);
                    return;
                }

                AdvanceDeletion(work, epoch, "removing", quarantine);
                if (batch.Removed == 0)
                {
                    break;
                }

                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, "deletion_pass_incomplete", recoveryRequired: false);
        }
        catch (OperationCanceledException)
        {
            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, "deletion_pass_interrupted", recoveryRequired: true);
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            var reason = failure switch
            {
                WorkspacePathException path => path.Reason,
                SandboxPrivateRootException root => root.Reason,
                _ => "deletion_observation_unavailable",
            };
            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, reason, recoveryRequired: true);
        }
        finally
        {
            lock (OwnershipGate)
            {
                _deletionWorkers.Remove(sandboxId);
            }
        }
    }

    private static bool IsMissingDeletionSource(Exception error) => error switch
    {
        WorkspacePathException path => path.Reason is "native_2" or "native_3",
        SandboxPrivateRootException root => root.Reason is "native_2" or "native_3",
        _ => false,
    };

    private (StoredSandbox Row, StoredSandboxDeletion Journal) GetDeletionWork(string sandboxId, byte[] epoch, string originalCommand)
    {
        lock (OwnershipGate)
        {
            return _store.Read(reader =>
            {
                var row = SandboxRecords.Get(reader, OwnerId, sandboxId);
                var journal = SandboxDeletionRecords.ReadOriginal(reader, OwnerId, epoch, sandboxId, originalCommand);
                if (row is null || journal is null || row.RootIdentity != journal.RootIdentity
                    || row.State is not (StoredSandboxState.Deleting or StoredSandboxState.RecoveryRequired)
                    || row.RootRelative != SandboxPrivateRoots.RelativePath(sandboxId))
                {
                    throw new DurableStoreMaintenanceException();
                }

                return (row, journal);
            });
        }
    }

    private void AdvanceDeletion((StoredSandbox Row, StoredSandboxDeletion Journal) work, byte[] epoch, string phase, string? quarantine)
    {
        lock (OwnershipGate)
        {
            _store.Write(transaction => RequireChanged(SandboxDeletionRecords.TryAdvance(transaction, work.Row, epoch,
                work.Journal, phase, quarantine)), CommitDurability.Full);
        }
    }

    private void CompleteDeletion((StoredSandbox Row, StoredSandboxDeletion Journal) work, byte[] epoch)
    {
        lock (OwnershipGate)
        {
            var original = Convert.FromHexString(work.Journal.OriginalCommandId);
            var successor = DeletionSuccessor(work.Journal);
            var result = ResultBody(checked(work.Row.Revision + 1), null);
            Receipts.SettleSandboxDeletion(original, successor, result, successor is null ? null : result,
                transaction => RequireChanged(SandboxDeletionRecords.TryComplete(transaction, work.Row, epoch, work.Journal)));
        }
    }

    private void RecordDeletionRemoval((StoredSandbox Row, StoredSandboxDeletion Journal) work, byte[] epoch)
    {
        lock (OwnershipGate)
        {
            Receipts.RecordSandboxRemovalVerified(Convert.FromHexString(work.Journal.OriginalCommandId),
                DeletionSuccessor(work.Journal), transaction =>
                {
                    if (SandboxRecords.Get(transaction, OwnerId, work.Row.SandboxId) != work.Row ||
                        SandboxDeletionRecords.ReadOriginal(transaction, OwnerId, epoch, work.Row.SandboxId,
                            work.Journal.OriginalCommandId) != work.Journal)
                    {
                        throw new DurableStoreMaintenanceException();
                    }
                });
        }
    }

    private void RecordDeleteUncertainty(string sandboxId, byte[] epoch, string originalCommand, string reason, bool recoveryRequired)
    {
        lock (OwnershipGate)
        {
            try
            {
                if (!epoch.AsSpan().SequenceEqual(Receipts.OwnerEpoch.Span))
                {
                    return;
                }

                var work = GetDeletionWork(sandboxId, epoch, originalCommand);
                var needsState = recoveryRequired && !work.Journal.RemovalVerified &&
                    work.Row.State != StoredSandboxState.RecoveryRequired;
                var revision = needsState ? checked(work.Row.Revision + 1) : work.Row.Revision;
                var result = ResultBody(revision, null, ErrorCategory.Execution, "outcome_unknown", reason);
                var successor = DeletionSuccessor(work.Journal);
                Receipts.MarkSandboxDeletionUnknown(Convert.FromHexString(originalCommand), successor, result,
                    successor is null ? null : result, needsState ? transaction =>
                        RequireChanged(SandboxDeletionRecords.TryAdvance(transaction, work.Row, epoch, work.Journal,
                            "recovery_required", work.Journal.QuarantineIdentity)) : null);
            }
            catch (Exception failure) when (IsDataFailure(failure))
            {
                // The exact original and any accepted successor remain durable for the next observation.
            }
        }
    }

    private static byte[]? DeletionSuccessor(StoredSandboxDeletion journal) =>
        journal.LatestSuccessorId is { } latest && journal.LatestSuccessorState is "ACCEPTED" or "UNKNOWN"
            ? Convert.FromHexString(latest) : null;
}
