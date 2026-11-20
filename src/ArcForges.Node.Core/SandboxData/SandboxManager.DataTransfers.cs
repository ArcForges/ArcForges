// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const long DataMaxFileBytes = 256L * 1024 * 1024;
    private const long DataMaxReservedBytes = 4 * DataMaxFileBytes;
    private static readonly TimeSpan DataEffectTimeout = TimeSpan.FromSeconds(25);
    private static readonly TimeSpan DataLifetime = TimeSpan.FromHours(1);
    private readonly object[] _dataTransferGates = Enumerable.Range(0, 32).Select(_ => new object()).ToArray();
    private readonly Dictionary<string, Task> _dataWorkers = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _dataStop = new();

    private readonly record struct DataMutation(StoredTransfer? Row, DurableReceipt? Receipt, ArcError? Error);

    private sealed class DataEffectException(ErrorCategory category, string code, string reason) : IOException(reason)
    {
        internal ErrorCategory Category { get; } = category;
        internal string Code { get; } = code;
    }

    private object DataTransferGate(string id) =>
        _dataTransferGates[(StringComparer.Ordinal.GetHashCode(id) & int.MaxValue) % _dataTransferGates.Length];

    private StoredTransfer? FindDataTransfer(Id id)
    {
        var row = _store.Read(reader => TransferRecords.Get(reader, OwnerId, ToHex(id)));
        return row is not null && row.Manifest.ActorId == OwnerId && row.Manifest.GrantId is null ? row : null;
    }

    private static ResponseMeta DataResponseMeta(RequestMeta meta, StoredTransfer? row) =>
        Response(meta, row?.Manifest.Revision);

    private static Transfer DataTransferView(StoredTransfer row)
    {
        var transfer = new Transfer
        {
            TransferId = FromHex(row.TransferId),
            SandboxId = FromHex(row.SandboxId),
            RelativePath = row.Manifest.RelativePath,
            State = (TransferState)row.State,
            ByteLength = checked((ulong)row.ByteLength),
            VerifiedOffset = checked((ulong)row.VerifiedOffset),
            ExpiresAt = ProtoTime.ToInstant(row.ExpiresAt),
            Direction = row.Direction == StoredTransferDirection.Import ? "import" : "export",
            ClosedAt = row.ClosedAt is { } closed ? ProtoTime.ToInstant(closed) : null,
        };
        if (row.ExpectedSha256.Length != 0)
        {
            transfer.Sha256 = row.ExpectedSha256;
        }

        return transfer;
    }

    private Operation DataOperation(StoredTransfer row, DurableReceipt receipt) => new()
    {
        CommandId = FromHex(receipt.CommandId),
        OwnerEpoch = FromBytes(row.OwnerEpoch),
        AggregateId = FromHex(row.TransferId),
        Method = receipt.Method,
        State = receipt.State switch
        {
            "ACCEPTED" => OperationState.Accepted,
            "SUCCEEDED" => OperationState.Succeeded,
            "FAILED" => OperationState.Failed,
            _ => OperationState.Unknown,
        },
        Effect = (EffectCertainty)receipt.Effect,
        Revision = new Revision { Value = ReadResult(receipt.ResponseJson).Revision ?? row.Manifest.Revision },
        UpdatedAt = ProtoTime.ToInstant(_store.Read(reader => reader.Scalar("""
            SELECT updated_utc FROM command_receipt WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$command;
            """, ("$owner", OwnerId), ("$epoch", row.OwnerEpoch), ("$command", receipt.CommandId))) is string updated
                ? DateTimeOffset.Parse(updated, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind)
                : row.ExpiresAt - DataLifetime),
    };

    private DataMutation StartDataTransfer(RequestMeta meta, Id ownerEpoch, Id sandbox, string relativePath,
        StoredTransferDirection direction, long? length, string sha256, bool overwrite, string? expectedFileVersion,
        IMessage canonical, CancellationToken cancellationToken)
    {
        var command = meta.CommandId.Value.ToByteArray();
        var epoch = ownerEpoch.Value.ToByteArray();
        var id = ToHex(sandbox);
        var method = direction == StoredTransferDirection.Import ? TransferRecords.BeginImportMethod : TransferRecords.BeginExportMethod;
        try
        {
            lock (OwnershipGate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var previous = Receipts.Inspect(command);
                var transferId = previous?.AggregateId ?? Guid.NewGuid().ToString("N");
                var intent = new DurableIntent(command, epoch, method, TransferRecords.Aggregate,
                    transferId, canonical.ToByteArray(), meta.ExpectedRev.Value, ExpectedSandboxId: id);
                if (previous is not null || !EpochMatches(ownerEpoch))
                {
                    return ResolveDataAdmission(meta, Receipts.Admit(intent));
                }

                var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, id));
                if (row is null)
                {
                    return new(null, null, NotFound(meta));
                }

                if (row.Revision != meta.ExpectedRev.Value)
                {
                    return new(null, null, RevisionError(meta, meta.ExpectedRev.Value, row.Revision));
                }

                if (row.State != StoredSandboxState.Ready || _dataStop.IsCancellationRequested ||
                    row.RootRelative != SandboxPrivateRoots.RelativePath(id))
                {
                    return DataFailure(meta, ErrorCategory.State, "busy", "sandbox_not_ready");
                }

                if (_store.Read(reader => TransferRecords.HasMutationGate(reader, OwnerId, id) || HasDataActiveRun(reader, id)))
                {
                    return DataFailure(meta, ErrorCategory.State, "managed_use", "sandbox_transfer_requires_quiescence");
                }

                ValidateDataPath(relativePath, allowRoot: false);
                if (!relativePath.Contains('/'))
                {
                    return DataFailure(meta, ErrorCategory.Validation, "invalid_argument", "owned_regular_file_required");
                }

                using var root = _roots.Inspect(id, row.RootIdentity);
                string? sourceVersion = null;
                string? parentIdentity = null;
                root.OwnedWorkspace.CheckSandboxDataName(relativePath, allowMissingFinal: direction == StoredTransferDirection.Import);
                if (direction == StoredTransferDirection.Export)
                {
                    var source = root.OwnedWorkspace.InspectEntry(relativePath);
                    if (source.Kind != WorkspaceEntryType.File || !source.Identity.IsFile || source.Identity.Links != 1
                        || source.Size is not { } bytes || bytes > long.MaxValue)
                    {
                        return DataFailure(meta, ErrorCategory.Validation, "invalid_argument", "owned_regular_file_required");
                    }

                    sourceVersion = DataFileVersion(id, relativePath, source);
                    if (expectedFileVersion is not null && expectedFileVersion != sourceVersion)
                    {
                        return DataFailure(meta, ErrorCategory.Conflict, "identity_changed", "source_file_version_changed");
                    }

                    length = checked((long)bytes);
                }
                else
                {
                    using var parent = root.OwnedWorkspace.OpenDirectory(DataParent(relativePath));
                    parentIdentity = WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(parent), directory: true);
                    CheckImportTarget(root.OwnedWorkspace, id, relativePath, overwrite, expectedFileVersion);
                }

                if (length is not long requested || requested < 0 || requested > DataMaxFileBytes
                    || _store.Read(reader => TransferRecords.ReservedBytes(reader, OwnerId)) > DataMaxReservedBytes - requested)
                {
                    return DataFailure(meta, ErrorCategory.Resource, "disk_space", "transfer_storage_limit");
                }

                using var staging = root.OpenTransferStaging();
                var storage = OperatingSystem.IsWindows() ? Path.GetPathRoot(staging.RootPath)! : staging.RootPath;
                if (new DriveInfo(storage).AvailableFreeSpace < requested + 8 * 1024 * 1024)
                {
                    return DataFailure(meta, ErrorCategory.Resource, "disk_space", "transfer_staging_capacity");
                }

                var beginCommand = ToHex(meta.CommandId);
                var manifest = new StoredTransferManifest(1, OwnerId, row.Revision, row.RootIdentity,
                    row.RootGeneration, relativePath, overwrite, expectedFileVersion,
                    Pending: new(StoredTransferPhase.Begin, beginCommand, TargetIdentity: sourceVersion, ParentIdentity: parentIdentity),
                    TargetParentIdentity: parentIdentity,
                    StageRootIdentity: WorkspacePath.EncodeDataIdentity(staging.RootIdentity, directory: true));
                var reserved = new StoredTransfer(transferId, id, OwnerId, epoch, beginCommand, direction,
                    StoredTransferState.Open, manifest, TransferRecords.UnboundStage, requested, 0, sha256,
                    _clock.GetUtcNow() + DataLifetime);
                var admission = Receipts.Admit(intent, transaction => TransferRecords.Reserve(transaction, reserved));
                if (admission.Decision != DurableDecision.Execute)
                {
                    return ResolveDataAdmission(meta, admission);
                }

                var work = Task.Run(() => RunDataBegin(reserved, command), CancellationToken.None);
                _dataWorkers.Add(transferId, work);
                return new(reserved, admission.Receipt, null);
            }
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            return new(null, null, DataError(meta, failure));
        }
    }

    private bool HasDataActiveRun(StoreReader reader, string sandboxId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM run AS r JOIN sandbox AS s ON s.sandbox_id=r.sandbox_id
                WHERE s.owner_id=$owner AND r.sandbox_id=$id AND r.state IN (1,2,3,4,7));
            """, ("$owner", OwnerId), ("$id", sandboxId)), 1L);

    private void RunDataBegin(StoredTransfer reserved, byte[] command)
    {
        try
        {
            lock (DataTransferGate(reserved.TransferId))
            {
                using var worker = CancellationTokenSource.CreateLinkedTokenSource(_dataStop.Token);
                worker.CancelAfter(DataEffectTimeout);
                var current = reserved;
                var attemptingCreate = false;
                var binding = false;
                StoredTransfer? completed = null;
                try
                {
                    worker.Token.ThrowIfCancellationRequested();
                    using var root = InspectDataRoot(current);
                    using var staging = OpenDataStaging(current);
                    attemptingCreate = true;
                    using (var stage = staging.CreateSandboxDataStage(current.TransferId))
                    {
                        var bound = NextDataRow(current, current.Manifest.Pending) with
                        {
                            StagingIdentity = WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(stage)),
                        };
                        binding = true;
                        AdvanceDataRow(current, bound);
                        binding = false;
                        current = bound;
                        if (current.Direction == StoredTransferDirection.Export)
                        {
                            var materialized = MaterializeDataExport(current, root.OwnedWorkspace, stage, worker.Token);
                            worker.Token.ThrowIfCancellationRequested();
                            stage.Dispose();
                            using var readStage = OpenDataStage(current, staging, writable: false);
                            var sealedSnapshot = SealDataExportSnapshot(materialized, readStage, worker.Token);
                            completed = sealedSnapshot with
                            {
                                Manifest = sealedSnapshot.Manifest with { Revision = checked(current.Manifest.Revision + 1), Pending = null },
                            };
                        }
                    }
                }
                catch (Exception failure) when (!binding && (IsDataFailure(failure) || failure is OperationCanceledException))
                {
                    if (current.StagingIdentity != TransferRecords.UnboundStage)
                    {
                        try
                        {
                            using var staging = OpenDataStaging(current);
                            staging.RemoveSandboxDataStage(current.TransferId, current.StagingIdentity, static () => { });
                            attemptingCreate = false;
                        }
                        catch (Exception cleanup) when (IsDataFailure(cleanup))
                        {
                            attemptingCreate = true;
                        }
                    }

                    var observation = DataError(null, failure);
                    var after = NextDataRow(current, attemptingCreate ? current.Manifest.Pending : null) with
                    {
                        State = attemptingCreate ? StoredTransferState.RecoveryRequired : StoredTransferState.Failed,
                        Effect = attemptingCreate ? (int)EffectCertainty.Unknown : (int)EffectCertainty.DidNotHappen,
                    };
                    SettleData(command, current, after, attemptingCreate ? "UNKNOWN" : "FAILED",
                        (EffectCertainty)after.Effect, observation);
                    return;
                }

                SettleData(command, current, completed ?? NextDataRow(current, null), "SUCCEEDED", EffectCertainty.Happened);
            }
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            // An uncommitted or accepted observation remains in the journal for recovery.
        }
        finally
        {
            lock (OwnershipGate)
            {
                _dataWorkers.Remove(reserved.TransferId);
            }
        }
    }

    private SandboxPrivateRootLease InspectDataRoot(StoredTransfer row)
    {
        var current = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, row.SandboxId));
        if (current is null || current.State != StoredSandboxState.Ready || current.Revision != row.Manifest.SandboxRevision
            || current.RootGeneration != row.Manifest.RootGeneration || current.RootIdentity != row.Manifest.RootIdentity
            || current.RootRelative != SandboxPrivateRoots.RelativePath(row.SandboxId))
        {
            throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "sandbox_transfer_root_changed");
        }

        return _roots.Inspect(row.SandboxId, row.Manifest.RootIdentity);
    }

    private WorkspacePath OpenDataStaging(StoredTransfer row)
    {
        var staging = _roots.OpenTransferStaging();
        if (WorkspacePath.EncodeDataIdentity(staging.RootIdentity, directory: true) == row.Manifest.StageRootIdentity)
        {
            return staging;
        }

        staging.Dispose();
        throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "transfer_stage_root_changed");
    }

    private static SafeFileHandle OpenDataStage(StoredTransfer row, WorkspacePath staging, bool writable) =>
        staging.OpenSandboxDataStage(row.TransferId, row.StagingIdentity, writable);

    private static StoredTransfer NextDataRow(StoredTransfer row, StoredTransferPending? pending) =>
        row with { Manifest = row.Manifest with { Revision = checked(row.Manifest.Revision + 1), Pending = pending } };

    private void AdvanceDataRow(StoredTransfer before, StoredTransfer after)
    {
        lock (OwnershipGate)
        {
            _store.Write(transaction => RequireChanged(TransferRecords.Advance(transaction, before, after)), CommitDurability.Full);
        }
    }

    private DurableReceipt SettleData(byte[] command, StoredTransfer before, StoredTransfer after, string state,
        EffectCertainty effect, ArcError? error = null)
    {
        lock (OwnershipGate)
        {
            return Receipts.SetResult(command, state, (int)effect,
                DataReceiptBody(after, error),
                transaction => RequireChanged(TransferRecords.Advance(transaction, before, after)));
        }
    }

    private DataMutation ResolveDataAdmission(RequestMeta meta, DurableAdmission admission)
    {
        var receipt = admission.Receipt;
        switch (admission.Decision)
        {
            case DurableDecision.Conflict:
                return DataFailure(meta, ErrorCategory.Conflict, "command_id_reused", "command_intent_changed");
            case DurableDecision.EpochRetired:
                return DataFailure(meta, ErrorCategory.Conflict, "owner_epoch_retired", "owner_epoch_mismatch");
            case DurableDecision.RevisionConflict:
                return DataFailure(meta, ErrorCategory.Conflict, "revision_mismatch", "sandbox_revision_changed");
            case DurableDecision.Capacity:
                return DataFailure(meta, ErrorCategory.Resource, "disk_space", "durable_receipt_capacity");
            case DurableDecision.Compacted when receipt is not null:
                var compacted = Error(meta, ErrorCategory.State, "receipt_compacted", "original_response_compacted",
                    (EffectCertainty)receipt.Effect);
                compacted.Details.State.State = receipt.State;
                compacted.Details.State.Resource = AggregateIdentity(receipt);
                compacted.Retry.ReconciliationOperation = "NodeService.GetOperation";
                return new(null, receipt, compacted);
        }

        if (receipt is not { AggregateKind: TransferRecords.Aggregate, AggregateId: { } id })
        {
            return new(null, null, StorageFailure(meta));
        }

        var row = FindDataTransfer(FromHex(id));
        if (row is not null && receipt.ResponseJson is { } body && receipt.State is "SUCCEEDED" or "FAILED")
        {
            row = ReadDataReceiptObservation(row, body);
        }

        if (receipt.State == "FAILED")
        {
            var result = ReadResult(receipt.ResponseJson);
            return new(row, receipt, Error(meta, result.Category, result.Code, result.Reason));
        }

        if (receipt.State == "UNKNOWN" && receipt.Method != TransferRecords.CommitMethod)
        {
            var result = ReadResult(receipt.ResponseJson);
            return new(row, receipt, Error(meta, ErrorCategory.Execution, "outcome_unknown", result.Reason, EffectCertainty.Unknown));
        }

        return row is null ? new(null, receipt, StorageFailure(meta)) : new(row, receipt, null);
    }

    private static string DataParent(string path) => path[..path.LastIndexOf('/')];

    private static DataMutation DataFailure(RequestMeta meta, ErrorCategory category, string code, string reason,
        EffectCertainty effect = EffectCertainty.DidNotHappen) =>
        new(null, null, Error(meta, category, code, reason, effect));

    private static bool IsDataFailure(Exception failure) =>
        IsStorageFailure(failure) || failure is RegisteredWorkspaceException;

    private static ArcError DataError(RequestMeta? meta, Exception failure) => failure switch
    {
        DataEffectException observed => Error(meta, observed.Category, observed.Code, observed.Message),
        WorkspacePathException { Reason: "native_28" or "native_112" } path =>
            Error(meta, ErrorCategory.Resource, "disk_space", path.Reason),
        WorkspacePathException { Reason: "native_17" or "native_80" or "native_183" } path =>
            Error(meta, ErrorCategory.Conflict, "identity_changed", path.Reason),
        WorkspacePathException { Reason: "path_case_collision" } path =>
            Error(meta, ErrorCategory.Conflict, "identity_changed", path.Reason),
        WorkspacePathException { Reason: "native_2" or "native_3" } path =>
            Error(meta, ErrorCategory.State, "not_found", path.Reason),
        WorkspacePathException path => Error(meta, ErrorCategory.Validation, "invalid_argument", path.Reason),
        SandboxPrivateRootException root => Error(meta, ErrorCategory.Conflict, "identity_changed", root.Reason),
        OperationCanceledException => Error(meta, ErrorCategory.Execution, "deadline", "data_worker_deadline"),
        _ => StorageFailure(meta),
    };

    private static void CheckImportTarget(WorkspacePath workspace, string sandboxId, string path, bool overwrite,
        string? expectedVersion)
    {
        WorkspaceEntryMetadata? actual = null;
        try
        {
            actual = workspace.InspectEntry(path);
        }
        catch (WorkspacePathException failure) when (failure.Reason is "native_2" or "native_3")
        {
            // An absent name is a valid destination only for native no-replace publication.
        }

        if (actual is null && !overwrite)
        {
            return;
        }

        if (actual is not { Kind: WorkspaceEntryType.File, Identity.Links: 1 } existing || !overwrite
            || DataFileVersion(sandboxId, path, existing) != expectedVersion)
        {
            throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "import_target_changed");
        }

        throw new DataEffectException(ErrorCategory.Execution, "unsupported_combination", "guarded_existing_file_replace_unavailable");
    }
}
