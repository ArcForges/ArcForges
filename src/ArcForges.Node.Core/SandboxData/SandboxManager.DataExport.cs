// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
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
    private const int ExportChunkLimit = 1_048_576;
    private const int ExportCopyBufferSize = 128 * 1024;

    internal DataServiceBeginExportResponse BeginDataExport(
        DataServiceBeginExportRequest request, CancellationToken cancellationToken)
    {
        var canonical = request.Clone();
        canonical.Meta = null;
        canonical.OwnerEpoch = null;
        var result = StartDataTransfer(request.Meta, request.OwnerEpoch, request.SandboxId, request.RelativePath,
            StoredTransferDirection.Export, null, string.Empty, overwrite: false,
            request.HasExpectedFileVersion ? request.ExpectedFileVersion : null, canonical, cancellationToken);
        var response = new DataServiceBeginExportResponse { Meta = DataResponseMeta(request.Meta, result.Row) };
        if (result.Error is { } error)
        {
            response.Error = error;
        }
        else if (result.Row is { } row)
        {
            response.Value = new DataServiceBeginExportValue { Transfer = DataTransferView(row) };
        }
        else
        {
            response.Error = StorageFailure(request.Meta);
        }

        return response;
    }

    internal DataServiceReadExportResponse ReadDataExport(
        DataServiceReadExportRequest request, CancellationToken cancellationToken)
    {
        var meta = request.Meta;
        if (!ValidId(request.TransferId) || !request.HasOffset || !request.HasMaxBytes
            || request.MaxBytes is 0 or > ExportChunkLimit)
        {
            return Failed(Error(meta, ErrorCategory.Validation, "invalid_argument", "export_read_shape_invalid"));
        }

        lock (DataTransferGate(ToHex(request.TransferId)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            StoredTransfer? row = null;
            try
            {
                row = FindDataTransfer(request.TransferId);
                if (row is null || row.Direction != StoredTransferDirection.Export)
                {
                    return Failed(NotFound(meta));
                }

                if (row.ClosedAt is not null)
                {
                    return Failed(Error(meta, ErrorCategory.State, "managed_use", "transfer_closed"), row);
                }

                if (row.ExpiresAt <= _clock.GetUtcNow())
                {
                    return Failed(Error(meta, ErrorCategory.State, "managed_use", "transfer_expired"), row);
                }

                if (row.State != StoredTransferState.Complete || row.Manifest.Pending is not null)
                {
                    return Failed(Error(meta, ErrorCategory.State, "managed_use", "export_snapshot_unavailable"), row);
                }

                if (request.Offset > (ulong)row.ByteLength)
                {
                    return Failed(Error(meta, ErrorCategory.Validation, "invalid_argument", "export_offset_invalid"), row);
                }

                using var staging = OpenDataStaging(row);
                using var file = OpenDataStage(row, staging, writable: false);
                RequireExportSnapshot(row, file);
                var offset = (long)request.Offset;
                var count = (int)Math.Min(row.ByteLength - offset, request.MaxBytes);
                var chunk = new DataChunk { Offset = request.Offset, Eof = offset + count == row.ByteLength };
                if (count != 0)
                {
                    byte[] bytes = new byte[count];
                    ReadExportRange(file, bytes, offset, cancellationToken);
                    chunk.Data = ByteString.CopyFrom(bytes);
                }

                RequireExportSnapshot(row, file);
                return new DataServiceReadExportResponse
                {
                    Meta = DataResponseMeta(meta, row),
                    Value = new DataServiceReadExportValue { Chunk = chunk },
                };
            }
            catch (WorkspacePathException failure)
            {
                return Failed(Error(meta, ErrorCategory.Conflict, "identity_changed", failure.Reason), row);
            }
            catch (SandboxPrivateRootException failure)
            {
                return Failed(Error(meta, ErrorCategory.Conflict, "identity_changed", failure.Reason), row);
            }
            catch (Exception failure) when (IsStorageFailure(failure))
            {
                return Failed(StorageFailure(meta), row);
            }
        }

        DataServiceReadExportResponse Failed(ArcError error, StoredTransfer? transfer = null) =>
            new() { Meta = DataResponseMeta(meta, transfer), Error = error };
    }

    private static StoredTransfer MaterializeDataExport(StoredTransfer row, WorkspacePath workspace,
        SafeFileHandle stage, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var relativePath = row.Manifest.RelativePath;
        using var source = workspace.OpenRead(relativePath);
        RequireDataExportSource(row, workspace, source);
        if (WorkspacePath.FileStamp(stage).Size != 0)
        {
            throw new WorkspacePathException("export_staging_changed");
        }

        string digest = HashDataExport(source, row.ByteLength, stage, cancellationToken);
        RequireDataExportSource(row, workspace, source);
        cancellationToken.ThrowIfCancellationRequested();
        RandomAccess.FlushToDisk(stage);
        return row with
        {
            State = StoredTransferState.Complete,
            VerifiedOffset = row.ByteLength,
            ExpectedSha256 = digest,
            Effect = (int)EffectCertainty.Happened,
        };
    }

    // Check the retained read-only object after the writer closes, when its native timestamps are final.
    private static StoredTransfer SealDataExportSnapshot(StoredTransfer row, SafeFileHandle readStage,
        CancellationToken cancellationToken)
    {
        string version = DataExportSnapshotVersion(row, readStage);
        string digest = HashDataExport(readStage, row.ByteLength, null, cancellationToken);
        if (digest != row.ExpectedSha256 || version != DataExportSnapshotVersion(row, readStage))
        {
            throw new WorkspacePathException("export_snapshot_changed");
        }

        return row with { Manifest = row.Manifest with { SnapshotVersion = version } };
    }

    private static void RequireDataExportSource(StoredTransfer row, WorkspacePath workspace, SafeFileHandle source)
    {
        string path = row.Manifest.RelativePath;
        var named = workspace.InspectEntry(path);
        var held = WorkspacePath.Identity(source);
        var stamp = WorkspacePath.FileStamp(source);
        if (named.Kind != WorkspaceEntryType.File || named.Identity.Links != 1 || !held.IsFile || held.Links != 1
            || !named.Identity.SameObject(held) || named.Stamp != stamp || stamp.Size != row.ByteLength
            || row.Manifest.Pending?.TargetIdentity != DataFileVersion(row.SandboxId, path, named))
        {
            throw new WorkspacePathException("export_source_changed");
        }
    }

    private static void RequireExportSnapshot(StoredTransfer row, SafeFileHandle file)
    {
        if (row.Manifest.SnapshotVersion != DataExportSnapshotVersion(row, file))
        {
            throw new WorkspacePathException("export_snapshot_changed");
        }
    }

    private static string DataExportSnapshotVersion(StoredTransfer row, SafeFileHandle file)
    {
        var identity = WorkspacePath.Identity(file);
        var stamp = WorkspacePath.FileStamp(file);
        if (!identity.IsFile || identity.Links != 1 || stamp.Size != row.ByteLength)
        {
            throw new WorkspacePathException("export_snapshot_changed");
        }

        var entry = new WorkspaceEntryMetadata(WorkspaceEntryType.File, (ulong)stamp.Size, identity, stamp);
        return DataFileVersion(row.TransferId, "export-snapshot", entry);
    }

    private static string HashDataExport(SafeFileHandle source, long length, SafeFileHandle? destination,
        CancellationToken cancellationToken)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ExportCopyBufferSize);
        try
        {
            for (long offset = 0; offset < length;)
            {
                var bytes = buffer.AsSpan(0, (int)Math.Min(length - offset, ExportCopyBufferSize));
                ReadExportRange(source, bytes, offset, cancellationToken);
                digest.AppendData(bytes);
                if (destination is not null)
                {
                    RandomAccess.Write(destination, bytes, offset);
                }

                offset += bytes.Length;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Convert.ToHexStringLower(digest.GetHashAndReset());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static void ReadExportRange(SafeFileHandle file, Span<byte> bytes, long offset, CancellationToken cancellationToken)
    {
        while (!bytes.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = RandomAccess.Read(file, bytes, offset);
            if (count == 0)
            {
                throw new WorkspacePathException("export_file_truncated");
            }

            bytes = bytes[count..];
            offset += count;
        }
    }
}
