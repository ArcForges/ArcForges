// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int DataRecoveryBatch = 16;
    private static readonly TimeSpan DataRecoveryInterval = TimeSpan.FromSeconds(2);
    private Task? _dataRecoveryTask;

    internal void StartDataRecovery()
    {
        lock (OwnershipGate)
        {
            if (!_dataStop.IsCancellationRequested)
            {
                _dataRecoveryTask ??= Task.Run(() => MaintainDataTransfersAsync(_dataStop.Token), CancellationToken.None);
            }
        }
    }

    internal void StopDataTransfers()
    {
        _dataStop.Cancel();
        StopDataUsageScans();
        Task[] workers;
        lock (OwnershipGate)
        {
            workers = _dataRecoveryTask is { } recovery ? [.. _dataWorkers.Values, recovery] : [.. _dataWorkers.Values];
        }

        Task.WhenAll(workers).GetAwaiter().GetResult();
        foreach (var gate in _dataTransferGates)
        {
            lock (gate)
            {
                // An already admitted RPC can still be unwinding on this transfer stripe.
            }
        }

        lock (_dataUsageGate)
        {
            while (_dataUsageActive != 0) Monitor.Wait(_dataUsageGate);
        }
    }

    private async Task MaintainDataTransfersAsync(CancellationToken cancellationToken)
    {
        string? pendingAfter = null;
        string? expiredAfter = null;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var pending = _store.Read(reader => TransferRecords.ListPending(reader, OwnerId, DataRecoveryBatch, pendingAfter));
                    var expired = _store.Read(reader => TransferRecords.ListExpired(reader, OwnerId, _clock.GetUtcNow(),
                        DataRecoveryBatch, expiredAfter));
                    pendingAfter = pending.Count == DataRecoveryBatch ? pending[^1].TransferId : null;
                    expiredAfter = expired.Count == DataRecoveryBatch ? expired[^1].TransferId : null;
                    foreach (var candidate in pending)
                        ReconcileDataTransfer(candidate.TransferId, mayExpire: false, cancellationToken);
                    foreach (var candidate in expired)
                        ReconcileDataTransfer(candidate.TransferId, mayExpire: true, cancellationToken);
                }
                catch (Exception failure) when (IsDataFailure(failure))
                {
                    // Leave durable effects for a later verified observation if the store could not be read or advanced.
                }

                await Task.Delay(DataRecoveryInterval, _clock, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void ReconcileDataTransfer(string transferId, bool mayExpire, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var gate = DataTransferGate(transferId);
        if (!Monitor.TryEnter(gate)) return;

        try
        {
            StoredTransfer? row;
            lock (OwnershipGate)
            {
                if (_dataWorkers.ContainsKey(transferId)) return;
                row = _store.Read(reader => TransferRecords.Get(reader, OwnerId, transferId));
                if (row is null || row.ClosedAt is not null || !row.OwnerEpoch.AsSpan().SequenceEqual(Receipts.OwnerEpoch.Span)) return;
            }

            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            budget.CancelAfter(DataEffectTimeout);
            if (row.Manifest.Pending is { } pending)
            {
                if (pending.Phase == StoredTransferPhase.Expire) RecoverDataExpiry(row, budget.Token);
                else RecoverDataReceipt(row, pending, budget.Token);
            }
            else if (mayExpire && _clock.GetUtcNow() >= row.ExpiresAt && row.State != StoredTransferState.RecoveryRequired
                && row.Effect != (int)EffectCertainty.Unknown)
            {
                var expiring = NextDataRow(row, new(StoredTransferPhase.Expire, CommandId: null, TargetIdentity: row.StagingIdentity));
                AdvanceDataRow(row, expiring);
                RecoverDataExpiry(expiring, budget.Token);
            }
        }
        catch (Exception failure) when (IsDataFailure(failure) || failure is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            // A failed observation must not discard an accepted command or release its reservation.
        }
        finally
        {
            Monitor.Exit(gate);
        }
    }

    private void RecoverDataReceipt(StoredTransfer row, StoredTransferPending pending, CancellationToken cancellationToken)
    {
        if (pending.CommandId is not { } id) return;
        var command = Convert.FromHexString(id);
        string? method = pending.Phase switch
        {
            StoredTransferPhase.Begin when row.Direction == StoredTransferDirection.Import => TransferRecords.BeginImportMethod,
            StoredTransferPhase.Begin => TransferRecords.BeginExportMethod,
            StoredTransferPhase.Chunk => TransferRecords.WriteMethod,
            StoredTransferPhase.Publish => TransferRecords.CommitMethod,
            StoredTransferPhase.Close => TransferRecords.CloseMethod,
            _ => null,
        };
        DurableReceipt? receipt;
        lock (OwnershipGate)
        {
            receipt = Receipts.Inspect(command);
        }

        if (method is null || receipt is not { State: "ACCEPTED" or "UNKNOWN", AggregateKind: TransferRecords.Aggregate }
            || receipt.CommandId != id || receipt.Method != method || receipt.AggregateId != row.TransferId) return;

        ArcError? observation = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool known = pending.Phase switch
            {
                StoredTransferPhase.Begin => RecoverDataBegin(row, command, cancellationToken),
                StoredTransferPhase.Chunk => RecoverDataChunk(row, pending, command, cancellationToken),
                StoredTransferPhase.Publish => RecoverDataPublication(row, pending, command, cancellationToken),
                StoredTransferPhase.Close => RecoverDataClose(row, command, cancellationToken),
                _ => false,
            };
            if (known) return;
        }
        catch (Exception failure) when (IsDataFailure(failure) || failure is OperationCanceledException && !_dataStop.IsCancellationRequested)
        {
            observation = DataError(null, failure);
        }

        if (receipt.State == "ACCEPTED" && !_dataStop.IsCancellationRequested)
        {
            lock (OwnershipGate)
            {
                if (Receipts.Inspect(command)?.State != "ACCEPTED") return;

                // Settlement uses the admitted command key; the receipt retains its original canonical intent.
                var intent = new DurableIntent(command, row.OwnerEpoch, method, TransferRecords.Aggregate, row.TransferId, []);
                _ = SettleDataUnknown(new RequestMeta(), intent, row, observation ?? Error(null, ErrorCategory.Execution,
                    "outcome_unknown", "transfer_recovery_evidence_unavailable", EffectCertainty.Unknown));
            }
        }
    }

    private bool RecoverDataBegin(StoredTransfer row, byte[] command, CancellationToken cancellationToken)
    {
        using var staging = OpenDataStaging(row);
        if (row.StagingIdentity == TransferRecords.UnboundStage)
        {
            if (!staging.InspectRemovalAbsent(row.TransferId)) return false;
            FlushRecoveredDataDirectory(staging.RootHandle);
            if (!staging.InspectRemovalAbsent(row.TransferId)) return false;
            FailRecoveredDataBegin(row, command, "transfer_stage_not_created");
            return true;
        }

        if (row.Direction == StoredTransferDirection.Export)
        {
            // ReadExport requires Complete with no pending journal. This export never made its snapshot available.
            if (!staging.InspectRemovalAbsent(row.TransferId))
            {
                cancellationToken.ThrowIfCancellationRequested();
                staging.RemoveSandboxDataStage(row.TransferId, row.StagingIdentity, static () => { });
            }

            FlushRecoveredDataDirectory(staging.RootHandle);
            if (!staging.InspectRemovalAbsent(row.TransferId)) return false;
            FailRecoveredDataBegin(row, command, "export_snapshot_interrupted");
            return true;
        }

        using var root = InspectDataRoot(row);
        using var stage = OpenDataStage(row, staging, writable: true);
        var stamp = WorkspacePath.FileStamp(stage);
        if (stamp.Size != 0) return false;
        RandomAccess.FlushToDisk(stage);
        FlushRecoveredDataDirectory(staging.RootHandle);
        if (WorkspacePath.FileStamp(stage) != stamp) return false;
        var opened = NextDataRow(row, null) with { State = StoredTransferState.Open, Effect = (int)EffectCertainty.DidNotHappen };
        SettleData(command, row, opened, "SUCCEEDED", EffectCertainty.Happened);
        return true;
    }

    private void FailRecoveredDataBegin(StoredTransfer row, byte[] command, string reason)
    {
        var failed = NextDataRow(row, null) with { State = StoredTransferState.Failed, Effect = (int)EffectCertainty.DidNotHappen };
        SettleData(command, row, failed, "FAILED", EffectCertainty.DidNotHappen, Error(null, ErrorCategory.State, "busy", reason));
    }

    private bool RecoverDataChunk(StoredTransfer row, StoredTransferPending pending, byte[] command, CancellationToken cancellationToken)
    {
        if (pending.Offset is not { } offset || pending.Length is not { } length || pending.Sha256 is null
            || row.StagingIdentity == TransferRecords.UnboundStage) return false;

        using var root = InspectDataRoot(row);
        using var staging = OpenDataStaging(row);
        using var stage = OpenDataStage(row, staging, writable: true);
        var stamp = WorkspacePath.FileStamp(stage);
        if (stamp.Size == offset)
        {
            var before = new WorkspaceEntryMetadata(WorkspaceEntryType.File, (ulong)offset, WorkspacePath.Identity(stage), stamp);
            if (DataFileVersion(row.TransferId, "import-stage", before) != pending.TargetIdentity
                || WorkspacePath.FileStamp(stage) != stamp) return false;
            var unwritten = NextDataRow(row, null) with
            {
                State = offset == 0 ? StoredTransferState.Open : StoredTransferState.Streaming,
                Effect = (int)EffectCertainty.DidNotHappen,
            };
            SettleData(command, row, unwritten, "FAILED", EffectCertainty.DidNotHappen,
                Error(null, ErrorCategory.State, "busy", "import_chunk_not_written"));
            return true;
        }

        var end = checked(offset + length);
        if (stamp.Size != end || !MatchesRecoveredDataChunk(stage, offset, checked((int)length), pending.Sha256, cancellationToken))
            return false;
        RandomAccess.FlushToDisk(stage);
        if (WorkspacePath.FileStamp(stage) != stamp) return false;
        var verified = NextDataRow(row, null) with
        {
            State = StoredTransferState.Streaming, VerifiedOffset = end, Effect = (int)EffectCertainty.DidNotHappen,
        };
        SettleData(command, row, verified, "SUCCEEDED", EffectCertainty.Happened);
        return true;
    }

    private static bool MatchesRecoveredDataChunk(SafeFileHandle file, long offset, int length, string expected,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var bytes = buffer.AsSpan(0, length);
            return ReadDataExactly(file, bytes, offset, cancellationToken) && Convert.ToHexStringLower(SHA256.HashData(bytes)) == expected;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private bool RecoverDataPublication(StoredTransfer row, StoredTransferPending pending, byte[] command,
        CancellationToken cancellationToken)
    {
        // Linux can re-establish publication durability on the exact held file and both directories.
        if (!OperatingSystem.IsLinux() || row.StagingIdentity == TransferRecords.UnboundStage || pending.TargetIdentity != row.StagingIdentity
            || pending.ParentIdentity is null || pending.ParentIdentity != row.Manifest.TargetParentIdentity) return false;

        using var root = InspectDataRoot(row);
        using var staging = OpenDataStaging(row);
        if (!staging.InspectRemovalAbsent(row.TransferId)) return false;
        var workspace = root.OwnedWorkspace;
        var path = row.Manifest.RelativePath;
        var parent = workspace.OpenDirectory(DataParent(path));
        if (WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(parent), directory: true) != pending.ParentIdentity) return false;

        using var target = workspace.OpenRead(path);
        var identity = WorkspacePath.Identity(target);
        var stamp = WorkspacePath.FileStamp(target);
        if (!identity.IsFile || identity.Links != 1 || WorkspacePath.EncodeDataIdentity(identity) != pending.TargetIdentity
            || !VerifyDataDigest(target, row.ByteLength, row.ExpectedSha256, cancellationToken)) return false;
        SyncRecoveredDataFile(target);
        FlushRecoveredDataDirectory(parent);
        FlushRecoveredDataDirectory(staging.RootHandle);

        var named = workspace.InspectEntry(path);
        var currentParent = workspace.OpenDirectory(DataParent(path));
        if (named.Kind != WorkspaceEntryType.File || named.Identity.Links != 1 || !identity.SameObject(named.Identity)
            || named.Stamp != stamp || WorkspacePath.FileStamp(target) != stamp || !staging.InspectRemovalAbsent(row.TransferId)
            || WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(currentParent), directory: true) != pending.ParentIdentity) return false;

        var published = NextDataRow(row, null) with { State = StoredTransferState.Complete, Effect = (int)EffectCertainty.Happened };
        SettleData(command, row, published, "SUCCEEDED", EffectCertainty.Happened);
        return true;
    }

    private bool RecoverDataClose(StoredTransfer row, byte[] command, CancellationToken cancellationToken)
    {
        if (!RecoverDataStageRelease(row, cancellationToken)) return false;
        var closed = ClosedDataRow(row, StoredTransferCloseReason.ExplicitClose);
        SettleData(command, row, closed, "SUCCEEDED", EffectCertainty.Happened);
        return true;
    }

    private void RecoverDataExpiry(StoredTransfer row, CancellationToken cancellationToken)
    {
        if (_clock.GetUtcNow() < row.ExpiresAt) return;
        try
        {
            if (RecoverDataStageRelease(row, cancellationToken))
            {
                AdvanceDataRow(row, ClosedDataRow(row, StoredTransferCloseReason.Expiry));
                return;
            }
        }
        catch (Exception failure) when (IsDataFailure(failure) || failure is OperationCanceledException && !_dataStop.IsCancellationRequested)
        {
            // The typed expiry journal remains when an exact release cannot be established.
        }

        if (!_dataStop.IsCancellationRequested && row.State is StoredTransferState.Open or StoredTransferState.Streaming)
        {
            AdvanceDataRow(row, NextDataRow(row, row.Manifest.Pending) with
            {
                State = StoredTransferState.RecoveryRequired, Effect = (int)EffectCertainty.Unknown,
            });
        }
    }

    private bool RecoverDataStageRelease(StoredTransfer row, CancellationToken cancellationToken)
    {
        if (row.Manifest.Pending?.TargetIdentity != row.StagingIdentity) return false;
        cancellationToken.ThrowIfCancellationRequested();
        using var staging = OpenDataStaging(row);
        if (!staging.InspectRemovalAbsent(row.TransferId))
        {
            if (row.StagingIdentity == TransferRecords.UnboundStage) return false;
            ReleaseDataStage(row);
        }

        FlushRecoveredDataDirectory(staging.RootHandle);
        return staging.InspectRemovalAbsent(row.TransferId);
    }

    private static void FlushRecoveredDataDirectory(SafeFileHandle directory)
    {
        if (OperatingSystem.IsLinux()) SyncRecoveredDataFile(directory);
    }

    private static void SyncRecoveredDataFile(SafeFileHandle file)
    {
        if (SyncDataRecoveryHandle(file) != 0)
            throw new WorkspacePathException($"native_{Marshal.GetLastPInvokeError()}");
    }

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int SyncDataRecoveryHandle(SafeFileHandle file);
}
