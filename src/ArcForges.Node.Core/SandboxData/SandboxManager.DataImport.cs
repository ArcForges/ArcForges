// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    internal DataServiceBeginImportResponse BeginDataImport(DataServiceBeginImportRequest request, CancellationToken cancellationToken) =>
        BeginDataImport(request, null, cancellationToken);

    private DataServiceBeginImportResponse BeginDataImport(DataServiceBeginImportRequest request, RemoteDataCall? remote,
        CancellationToken cancellationToken)
    {
        var canonical = request.Clone();
        canonical.Meta = null;
        canonical.OwnerEpoch = null;
        var result = request.ByteLength > long.MaxValue
            ? DataFailure(request.Meta, ErrorCategory.Resource, "disk_space", "transfer_storage_limit")
            : StartDataTransfer(request.Meta, request.OwnerEpoch, request.SandboxId, request.RelativePath,
                StoredTransferDirection.Import, checked((long)request.ByteLength), request.Sha256, request.Overwrite,
                request.HasExpectedFileVersion ? request.ExpectedFileVersion : null, canonical, remote, cancellationToken);
        if (result is { Error: null, Row: { } row, Receipt.State: "ACCEPTED" })
        {
            result = AwaitDataImportStage(request.Meta, row, remote?.Binding, cancellationToken);
        }

        var response = new DataServiceBeginImportResponse { Meta = DataResponseMeta(request.Meta, result.Row) };
        if (result.Error is { } error)
        {
            response.Error = error;
        }
        else
        {
            response.Value = new() { Transfer = DataTransferView(result.Row!) };
        }

        return response;
    }

    private DataMutation AwaitDataImportStage(RequestMeta meta, StoredTransfer row, DurableRemoteBinding? remote,
        CancellationToken cancellationToken)
    {
        try
        {
            Task? worker;
            lock (OwnershipGate)
            {
                _dataWorkers.TryGetValue(row.TransferId, out worker);
            }

            // OPEN is the usable import stage state. Do not advertise it while Begin still owns unverified staging.
            worker?.WaitAsync(cancellationToken).GetAwaiter().GetResult();
            lock (OwnershipGate)
            {
                var receipt = Receipts.Inspect(meta.CommandId.Value.ToByteArray());
                if (receipt is { State: "ACCEPTED" })
                {
                    var pending = Error(meta, ErrorCategory.Execution, "outcome_unknown",
                        "import_stage_pending_reconciliation", EffectCertainty.Unknown);
                    pending.Details.State.Resource = AggregateIdentity(receipt);
                    return new(row, receipt, pending);
                }

                return ResolveDataAdmission(meta, new(receipt?.Compacted == true ? DurableDecision.Compacted : DurableDecision.Replay, receipt),
                    remote);
            }
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            return new(row, null, DataError(meta, failure));
        }
    }

    internal DataServiceWriteImportResponse WriteDataImport(DataServiceWriteImportRequest request, CancellationToken cancellationToken) =>
        WriteDataImport(request, null, cancellationToken);

    private DataServiceWriteImportResponse WriteDataImport(DataServiceWriteImportRequest request, RemoteDataCall? remote,
        CancellationToken cancellationToken)
    {
        var chunkHash = SHA256.HashData(request.Chunk.Span);
        Span<byte> contentIdentity = stackalloc byte[sizeof(int) + SHA256.HashSizeInBytes];
        BinaryPrimitives.WriteInt32LittleEndian(contentIdentity, request.Chunk.Length);
        chunkHash.CopyTo(contentIdentity[sizeof(int)..]);
        var canonical = request.Clone();
        canonical.Meta = DataCanonicalMeta(request.Meta);
        canonical.OwnerEpoch = null;
        // The private intent contains the exact content identity, not a second wire-sized payload.
        canonical.Chunk = ByteString.CopyFrom(contentIdentity);
        var result = ExecuteDataMutation(request.Meta, request.OwnerEpoch, request.TransferId, TransferRecords.WriteMethod,
            canonical, (row, intent) => WriteDataChunk(request.Meta, row, intent, request.Offset, request.Chunk, chunkHash, remote, cancellationToken),
            remote, cancellationToken);
        var response = new DataServiceWriteImportResponse { Meta = DataResponseMeta(request.Meta, result.Row) };
        if (result.Error is { } error)
        {
            response.Error = error;
        }
        else
        {
            response.Value = new() { Transfer = DataTransferView(result.Row!) };
        }

        return response;
    }

    internal DataServiceCommitImportResponse CommitDataImport(DataServiceCommitImportRequest request, CancellationToken cancellationToken) =>
        CommitDataImport(request, null, cancellationToken);

    private DataServiceCommitImportResponse CommitDataImport(DataServiceCommitImportRequest request, RemoteDataCall? remote,
        CancellationToken cancellationToken)
    {
        var canonical = request.Clone();
        canonical.Meta = DataCanonicalMeta(request.Meta);
        canonical.OwnerEpoch = null;
        var result = ExecuteDataMutation(request.Meta, request.OwnerEpoch, request.TransferId, TransferRecords.CommitMethod,
            canonical, (row, intent) => PublishDataImport(request.Meta, row, intent, remote, cancellationToken), remote, cancellationToken);
        var response = new DataServiceCommitImportResponse { Meta = DataResponseMeta(request.Meta, result.Row) };
        if (result.Error is { } error)
        {
            response.Error = error;
        }
        else
        {
            var row = result.Row!;
            response.Value = new() { Transfer = DataTransferView(row), Operation = DataOperation(row, result.Receipt!) };
        }

        return response;
    }

    internal DataServiceInspectTransferResponse InspectDataTransfer(DataServiceInspectTransferRequest request, CancellationToken cancellationToken) =>
        InspectDataTransfer(request, null, cancellationToken);

    private DataServiceInspectTransferResponse InspectDataTransfer(DataServiceInspectTransferRequest request,
        RemoteDataCall? remote, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var row = FindDataTransferForCall(request.TransferId, remote);
            return row is null
                ? new() { Meta = Response(request.Meta), Error = NotFound(request.Meta) }
                : new() { Meta = DataResponseMeta(request.Meta, row), Value = new() { Transfer = DataTransferView(row) } };
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return new() { Meta = Response(request.Meta), Error = StorageFailure(request.Meta) };
        }
    }

    internal DataServiceCloseTransferResponse CloseDataTransfer(DataServiceCloseTransferRequest request, CancellationToken cancellationToken) =>
        CloseDataTransfer(request, null, cancellationToken);

    private DataServiceCloseTransferResponse CloseDataTransfer(DataServiceCloseTransferRequest request, RemoteDataCall? remote,
        CancellationToken cancellationToken)
    {
        var canonical = request.Clone();
        canonical.Meta = DataCanonicalMeta(request.Meta);
        canonical.OwnerEpoch = null;
        var result = ExecuteDataMutation(request.Meta, request.OwnerEpoch, request.TransferId, TransferRecords.CloseMethod,
            canonical, (row, intent) => CloseDataEffect(request.Meta, row, intent, remote, cancellationToken), remote, cancellationToken);
        var response = new DataServiceCloseTransferResponse { Meta = DataResponseMeta(request.Meta, result.Row) };
        if (result.Error is { } error)
        {
            response.Error = error;
        }
        else
        {
            response.Value = new() { Transfer = DataTransferView(result.Row!) };
        }

        return response;
    }

    private static RequestMeta DataCanonicalMeta(RequestMeta original) => new() { ExpectedRev = original.ExpectedRev.Clone() };

    private DataMutation ExecuteDataMutation(RequestMeta meta, Id epoch, Id id, string method, IMessage canonical,
        Func<StoredTransfer, DurableIntent, DataMutation> execute, RemoteDataCall? remote, CancellationToken cancellationToken)
    {
        var transferId = ToHex(id);
        var command = meta.CommandId.Value.ToByteArray();
        lock (DataTransferGate(transferId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                StoredTransfer? row;
                DurableIntent intent;
                lock (OwnershipGate)
                {
                    if (remote is not null && !EpochMatches(epoch)) return new(null, null, RetiredRunEpoch(meta));

                    var previous = Receipts.Inspect(command);
                    row = FindDataTransferForCall(id, remote);
                    if (remote is not null && (row is null || previous is not null && previous.Remote != remote.Binding))
                        return new(null, null, GrantDenied(meta));

                    string? safetyParent = null;
                    if (method == TransferRecords.CloseMethod)
                    {
                        safetyParent = previous?.Method == TransferRecords.CloseMethod
                            ? previous.SafetyParentCommandId
                            : row is { ClosedAt: null } ? row.BeginCommandId : null;
                    }

                    intent = new DurableIntent(command, epoch.Value.ToByteArray(), method, TransferRecords.Aggregate,
                        transferId, canonical.ToByteArray(),
                        SafetyParent: safetyParent is null ? null : Convert.FromHexString(safetyParent), Remote: remote?.Binding);
                    if (previous is not null || !EpochMatches(epoch))
                    {
                        return ResolveDataAdmission(meta, TrackDataAdmission(remote, () => Receipts.Admit(intent)), intent.Remote);
                    }

                    if (row is null || !row.OwnerEpoch.AsSpan().SequenceEqual(epoch.Value.Span))
                    {
                        return new(null, null, NotFound(meta));
                    }

                    if (row.Manifest.Revision != meta.ExpectedRev.Value)
                    {
                        return new(row, null, RevisionError(meta, meta.ExpectedRev.Value, row.Manifest.Revision));
                    }

                    if (row.Manifest.Pending is not null || row.State == StoredTransferState.RecoveryRequired)
                    {
                        return new(row, null, Error(meta, ErrorCategory.State, "managed_use", "transfer_effect_unresolved",
                            remote is null && row.Effect == (int)EffectCertainty.Unknown ? EffectCertainty.Unknown : EffectCertainty.DidNotHappen));
                    }

                    if (method != TransferRecords.CloseMethod && (row.ClosedAt is not null || row.ExpiresAt <= _clock.GetUtcNow()))
                    {
                        return new(row, null, Error(meta, ErrorCategory.State, "managed_use", "transfer_closed_or_expired"));
                    }

                    if (_dataStop.IsCancellationRequested)
                    {
                        return new(row, null, Error(meta, ErrorCategory.State, "busy", "data_worker_stopping"));
                    }
                }

                return execute(row, intent);
            }
            catch (Exception failure) when (IsDataFailure(failure))
            {
                return new(null, null, DataError(meta, failure));
            }
        }
    }

    private DataMutation WriteDataChunk(RequestMeta meta, StoredTransfer row, DurableIntent intent, ulong offset,
        ByteString bytes, byte[] chunkHash, RemoteDataCall? remote, CancellationToken cancellationToken)
    {
        if (row.Direction != StoredTransferDirection.Import || row.State is not (StoredTransferState.Open or StoredTransferState.Streaming)
            || offset > (ulong)row.VerifiedOffset || bytes.Length is <= 0 or > 1_048_576
            || (ulong)bytes.Length > (ulong)row.ByteLength - offset)
        {
            return new(row, null, Error(meta, ErrorCategory.Conflict, "revision_mismatch", "import_offset_or_state_invalid"));
        }

        using var root = InspectDataRoot(row);
        using var staging = OpenDataStaging(row);
        using var stage = OpenDataStage(row, staging, writable: offset == (ulong)row.VerifiedOffset);
        if (RandomAccess.GetLength(stage) != row.VerifiedOffset)
        {
            return new(row, null, Error(meta, ErrorCategory.Conflict, "identity_changed", "import_stage_length_changed"));
        }

        if (offset < (ulong)row.VerifiedOffset)
        {
            if ((ulong)bytes.Length > (ulong)row.VerifiedOffset - offset)
            {
                return new(row, null, Error(meta, ErrorCategory.Conflict, "revision_mismatch", "import_chunk_overlap"));
            }

            var previous = ArrayPool<byte>.Shared.Rent(bytes.Length);
            try
            {
                var slice = previous.AsSpan(0, bytes.Length);
                if (!ReadDataExactly(stage, slice, checked((long)offset), cancellationToken) ||
                    !CryptographicOperations.FixedTimeEquals(slice, bytes.Span))
                {
                    return new(row, null, Error(meta, ErrorCategory.Conflict, "identity_changed", "import_chunk_changed"));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(previous, clearArray: true);
            }

            lock (OwnershipGate)
            {
                RequireRemoteDataCallCurrent(remote);
                var observed = TrackDataAdmission(remote, () => Receipts.AdmitObserved(intent, "SUCCEEDED", (int)EffectCertainty.Happened,
                    DataReceiptBody(row)));
                return ResolveDataAdmission(meta, observed, intent.Remote);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        var checkpoint = new WorkspaceEntryMetadata(WorkspaceEntryType.File, (ulong)row.VerifiedOffset,
            WorkspacePath.Identity(stage), WorkspacePath.FileStamp(stage));
        var recorded = new StoredTransferPending(StoredTransferPhase.Chunk, Convert.ToHexStringLower(intent.CommandId),
            checked((long)offset), bytes.Length, Convert.ToHexStringLower(chunkHash),
            TargetIdentity: DataFileVersion(row.TransferId, "import-stage", checkpoint));
        var pending = NextDataRow(row, recorded);
        var admission = AdmitDataStep(intent, row, pending, remote);
        if (admission.Decision != DurableDecision.Execute)
        {
            return ResolveDataAdmission(meta, admission, intent.Remote);
        }

        try
        {
            RandomAccess.Write(stage, bytes.Span, checked((long)offset));
            WorkspacePath.FlushSandboxDataFile(stage);
            if (RandomAccess.GetLength(stage) != row.VerifiedOffset + bytes.Length)
            {
                throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "import_stage_length_changed");
            }
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            return SettleDataUnknown(meta, intent, pending, DataError(meta, failure));
        }

        var after = NextDataRow(pending, null) with
        {
            State = StoredTransferState.Streaming,
            VerifiedOffset = checked(row.VerifiedOffset + bytes.Length),
        };
        return new(after, SettleData(intent.CommandId, pending, after, "SUCCEEDED", EffectCertainty.Happened), null);
    }

    private DataMutation PublishDataImport(RequestMeta meta, StoredTransfer row, DurableIntent intent, RemoteDataCall? remote,
        CancellationToken cancellationToken)
    {
        if (row.Direction != StoredTransferDirection.Import || row.State is not (StoredTransferState.Open or StoredTransferState.Streaming)
            || row.VerifiedOffset != row.ByteLength)
        {
            return new(row, null, Error(meta, ErrorCategory.State, "managed_use", "import_bytes_incomplete"));
        }

        using var staging = OpenDataStaging(row);
        using var stage = OpenDataStage(row, staging, writable: true);
        using var worker = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _dataStop.Token);
        worker.CancelAfter(DataEffectTimeout);
        if (!VerifyDataDigest(stage, row.ByteLength, row.ExpectedSha256, worker.Token))
        {
            return new(row, null, Error(meta, ErrorCategory.Conflict, "identity_changed", "import_digest_mismatch"));
        }

        lock (OwnershipGate)
        {
            return PublishValidatedDataImport(meta, row, intent, staging, stage, remote, worker.Token);
        }
    }

    private DataMutation PublishValidatedDataImport(RequestMeta meta, StoredTransfer row, DurableIntent intent,
        WorkspacePath staging, SafeFileHandle stage, RemoteDataCall? remote, CancellationToken cancellationToken)
    {
        var path = row.Manifest.RelativePath;
        using var root = InspectDataRoot(row);
        root.OwnedWorkspace.CheckSandboxDataName(path, allowMissingFinal: true);
        using var parent = root.OwnedWorkspace.OpenDirectory(DataParent(path));
        var parentIdentity = WorkspacePath.EncodeDataIdentity(WorkspacePath.Identity(parent), directory: true);
        if (parentIdentity != row.Manifest.TargetParentIdentity)
        {
            return new(row, null, Error(meta, ErrorCategory.Conflict, "identity_changed", "import_parent_changed"));
        }

        CheckImportTarget(root.OwnedWorkspace, row.SandboxId, path, row.Manifest.Overwrite, row.Manifest.ExpectedFileVersion);
        cancellationToken.ThrowIfCancellationRequested();
        var recorded = new StoredTransferPending(StoredTransferPhase.Publish, Convert.ToHexStringLower(intent.CommandId),
            TargetIdentity: row.StagingIdentity, ParentIdentity: parentIdentity);
        var pending = NextDataRow(row, recorded);
        HoldRunFault("hold-data-before-commit-intent");
        var admission = remote is null
            ? Receipts.Admit(intent, transaction => RequireChanged(TransferRecords.Advance(transaction, row, pending)))
            : AdmitDataStep(intent, row, pending, remote);
        if (admission.Decision != DurableDecision.Execute)
        {
            return ResolveDataAdmission(meta, admission, intent.Remote);
        }

        var applied = false;
        try
        {
            HoldRunFault("hold-data-after-commit-intent");
            using var checkedRoot = InspectDataRoot(row);
            using var checkedParent = checkedRoot.OwnedWorkspace.OpenDirectory(DataParent(path));
            if (!WorkspacePath.Identity(parent).SameObject(WorkspacePath.Identity(checkedParent)))
            {
                throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "import_parent_changed");
            }

            checkedRoot.OwnedWorkspace.CheckSandboxDataName(path, allowMissingFinal: true);
            staging.PublishSandboxDataStage(stage, row.TransferId, parent, path[(path.LastIndexOf('/') + 1)..],
                () =>
                {
                    applied = true;
                    HoldRunFault("hold-data-after-first-publication-effect");
                });
            if (!applied)
            {
                return SettleDataUnknown(meta, intent, pending,
                    Error(meta, ErrorCategory.Execution, "outcome_unknown", "import_publish_unconfirmed", EffectCertainty.Unknown));
            }

            using var publishedRoot = InspectDataRoot(row);
            using var publishedParent = publishedRoot.OwnedWorkspace.OpenDirectory(DataParent(path));
            var actual = publishedRoot.OwnedWorkspace.InspectEntry(path);
            if (!WorkspacePath.Identity(parent).SameObject(WorkspacePath.Identity(publishedParent))
                || actual.Kind != WorkspaceEntryType.File || actual.Identity.Links != 1
                || !actual.Identity.SameObject(WorkspacePath.Identity(stage)) || actual.Size != (ulong)row.ByteLength)
            {
                throw new DataEffectException(ErrorCategory.Conflict, "identity_changed", "import_publication_identity_changed");
            }

            publishedRoot.OwnedWorkspace.CheckSandboxDataName(path, allowMissingFinal: false);
            HoldRunFault("hold-data-after-publication");
        }
        catch (Exception failure) when (IsDataFailure(failure))
        {
            var observed = DataError(meta, failure);
            if (applied)
            {
                return SettleDataUnknown(meta, intent, pending, observed);
            }

            var refused = NextDataRow(pending, null);
            var known = SettleData(intent.CommandId, pending, refused, "FAILED", EffectCertainty.DidNotHappen, observed);
            return new(refused, known, observed);
        }

        var after = NextDataRow(pending, null) with { State = StoredTransferState.Complete, Effect = (int)EffectCertainty.Happened };
        var receipt = SettleData(intent.CommandId, pending, after, "SUCCEEDED", EffectCertainty.Happened);
        HoldRunFault("hold-data-before-commit-reply");
        return new(after, receipt, null);
    }

    private DurableAdmission AdmitDataStep(DurableIntent intent, StoredTransfer before, StoredTransfer after, RemoteDataCall? remote)
    {
        lock (OwnershipGate)
        {
            RequireRemoteDataCallCurrent(remote);
            return TrackDataAdmission(remote, () => Receipts.Admit(intent,
                transaction => RequireChanged(TransferRecords.Advance(transaction, before, after))));
        }
    }

    private DataMutation SettleDataUnknown(RequestMeta meta, DurableIntent intent, StoredTransfer pending, ArcError observed)
    {
        // A complete snapshot keeps its outcome while the separate closure remains unsettled.
        var after = NextDataRow(pending, pending.Manifest.Pending);
        if (after.State != StoredTransferState.Complete)
        {
            after = after with { State = StoredTransferState.RecoveryRequired, Effect = (int)EffectCertainty.Unknown };
        }

        var receipt = SettleData(intent.CommandId, pending, after, "UNKNOWN", EffectCertainty.Unknown, observed);
        return intent.Method == TransferRecords.CommitMethod
            ? new(after, receipt, null)
            : new(after, receipt, Error(meta, ErrorCategory.Execution, "outcome_unknown",
                observed.Details.State.Reason, EffectCertainty.Unknown));
    }

    private static bool VerifyDataDigest(SafeFileHandle stage, long length, string expected, CancellationToken cancellationToken)
    {
        if (RandomAccess.GetLength(stage) != length)
        {
            return false;
        }

        var stamp = WorkspacePath.FileStamp(stage);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(128 * 1024);
        try
        {
            for (long offset = 0; offset < length;)
            {
                var slice = buffer.AsSpan(0, (int)Math.Min(length - offset, 128 * 1024));
                if (!ReadDataExactly(stage, slice, offset, cancellationToken))
                {
                    return false;
                }

                digest.AppendData(slice);
                offset += slice.Length;
            }

            return stamp == WorkspacePath.FileStamp(stage)
                && CryptographicOperations.FixedTimeEquals(digest.GetHashAndReset(), Convert.FromHexString(expected));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static bool ReadDataExactly(SafeFileHandle file, Span<byte> buffer, long offset, CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = RandomAccess.Read(file, buffer, offset);
            if (read == 0)
            {
                return false;
            }

            buffer = buffer[read..];
            offset += read;
        }

        return true;
    }
}
