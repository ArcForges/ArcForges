// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int DeleteBatchSize = 128;
    private const int DeleteBatchLimit = 16;
    private static readonly TimeSpan DeletePassLimit = TimeSpan.FromSeconds(8);
    private readonly Dictionary<string, Task> _deletionWorkers = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _deleteStop = new();
    private bool _deleteStopping;

    internal NodeLog? DeletionLog { get; init; }

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
                        item.Journal.Phase, "deletion_worker_interrupted", recoveryRequired: true);
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
        string phase = "locked";
        try
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(_deleteStop.Token);
            budget.CancelAfter(DeletePassLimit);
            HoldRunFault("hold-delete-after-lock");
            var work = GetDeletionWork(sandboxId, epoch, originalCommand);
            var quarantine = work.Journal.QuarantineIdentity;
            if (work.Journal.RemovalVerified && quarantine is not null)
            {
                phase = "verify_removal";
                _roots.VerifyRecordedRemoval(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId, quarantine);
                phase = "tombstone";
                CompleteDeletion(work, epoch);
                return;
            }

            if (quarantine is null)
            {
                phase = "quarantine";
                var moved = false;
                try
                {
                    budget.Token.ThrowIfCancellationRequested();
                    quarantine = _roots.QuarantineDeletion(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId,
                        () => moved = true, budget.Token);
                }
                catch (Exception failure) when (!moved && IsMissingDeletionSource(failure))
                {
                    ReportDeletion(sandboxId, originalCommand, phase, "source_missing", DeletionFailureReason(failure));
                    phase = "observe_quarantine";
                    quarantine = _roots.ObserveQuarantinedDeletion(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId);
                }

                phase = "persist_quarantine";
                AdvanceDeletion(work, epoch, "quarantined", quarantine);
                HoldRunFault("hold-delete-after-quarantine");
                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            if (work.Journal.Phase != "removing")
            {
                phase = "persist_removal_phase";
                AdvanceDeletion(work, epoch, "removing", quarantine);
                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            for (var index = 0; index < DeleteBatchLimit; index++)
            {
                phase = "removing";
                budget.Token.ThrowIfCancellationRequested();
                var batch = _roots.RemoveDeletionBatch(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId,
                    quarantine, DeleteBatchSize, () => HoldRunFault("hold-delete-during-removal"), budget.Token);
                if (batch.RootAbsent)
                {
                    phase = "verify_removal";
                    HoldRunFault("hold-delete-before-removal-proof");
                    _roots.VerifyRecordedRemoval(sandboxId, work.Journal.RootIdentity, work.Journal.DeletionId, quarantine);
                    phase = "persist_removal_proof";
                    RecordDeletionRemoval(work, epoch);
                    HoldRunFault("hold-delete-before-tombstone");
                    phase = "tombstone";
                    CompleteDeletion(GetDeletionWork(sandboxId, epoch, originalCommand), epoch);
                    return;
                }

                phase = "persist_removal_progress";
                AdvanceDeletion(work, epoch, "removing", quarantine);
                if (batch.Removed == 0)
                {
                    break;
                }

                work = GetDeletionWork(sandboxId, epoch, originalCommand);
            }

            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, "removing", "deletion_pass_incomplete", recoveryRequired: false);
        }
        catch (OperationCanceledException)
        {
            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, phase, "deletion_pass_interrupted", recoveryRequired: true);
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            var reason = failure switch
            {
                WorkspacePathException path => path.Reason,
                SandboxPrivateRootException root => root.Reason,
                _ => "deletion_observation_unavailable",
            };
            RecordDeleteUncertainty(sandboxId, epoch, originalCommand, phase, reason, recoveryRequired: true,
                diagnosticReason: DeletionFailureReason(failure));
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

    private static string DeletionFailureReason(Exception failure) => failure switch
    {
        WorkspacePathException path => path.Reason,
        SandboxPrivateRootException root => root.Reason,
        SqliteException sqlite => "sqlite_" + sqlite.SqliteExtendedErrorCode.ToString(CultureInfo.InvariantCulture),
        _ => failure.GetType().Name,
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

        ReportDeletion(work.Row.SandboxId, work.Journal.OriginalCommandId, "tombstone", "succeeded", "owned_root_removal_verified");
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

    private void RecordDeleteUncertainty(string sandboxId, byte[] epoch, string originalCommand, string phase, string reason,
        bool recoveryRequired, string? diagnosticReason = null)
    {
        var observedReason = diagnosticReason ?? reason;
        ReportDeletion(sandboxId, originalCommand, phase, "unknown", observedReason);
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
                ReportDeletion(sandboxId, originalCommand, phase, "unknown", observedReason, failure);
            }
        }
    }

    private void ReportDeletion(string? sandboxId, string? operationId, string phase, string outcome, string? reason = null,
        Exception? persistenceFailure = null)
    {
        if (DeletionLog is not { } log)
        {
            return;
        }

        var sandbox = new LogField("sandboxId", sandboxId is not null && IsSandboxId(sandboxId) ? sandboxId : null);
        var operation = new LogField("operationId", operationId is not null && IsSandboxId(operationId) ? operationId : null);
        var stage = new LogField("phase", DeleteDiagnosticToken(phase));
        var state = new LogField("outcome", DeleteDiagnosticToken(outcome));
        var observed = new LogField("reason", DeleteDiagnosticToken(reason));
        if (persistenceFailure is not null)
        {
            log.Warning("sandbox.deletion.persist_failed", sandbox, operation, stage, state, observed,
                new LogField("persistenceReason", DeleteDiagnosticToken(DeletionFailureReason(persistenceFailure))),
                new LogField("persistenceErrorType", persistenceFailure.GetType().Name));
            return;
        }

        var level = outcome is "succeeded" or "source_missing" ? LogLevel.Info : LogLevel.Warning;
        log.Write(level, "sandbox.deletion", sandbox, operation, stage, state, observed);
    }

    private static string? DeleteDiagnosticToken(string? value) => value is null ||
        value.Length is > 0 and <= 96 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-')
            ? value : "diagnostic_reason_redacted";

    private static byte[]? DeletionSuccessor(StoredSandboxDeletion journal) =>
        journal.LatestSuccessorId is { } latest && journal.LatestSuccessorState is "ACCEPTED" or "UNKNOWN"
            ? Convert.FromHexString(latest) : null;
}
