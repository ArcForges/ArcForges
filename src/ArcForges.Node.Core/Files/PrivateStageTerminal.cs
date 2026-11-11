// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Durable no-target-effect settlement for a failed pre-approval producer or a terminal rejected approval.
/// It preserves every retained stage and its byte charge; it never adopts a PREPARED journal or a live approval.
/// </summary>
internal static class PrivateStageTerminal
{
    private enum Reason { ProducerAbandoned = 1, ApprovalDenied = 2, ApprovalExpired = 3, ApprovalCancelled = 4 }

    private sealed record Terminal(byte[] Id, FileOperationKind Kind, byte[] Digest, CenterCaller Caller, byte[] Correlation,
        byte[] Workspace, string Path, long Created, long Completed, Reason Why, byte[] Outcome);

    /// <summary>Called only at startup, after prior effect journals have been recovered.</summary>
    internal static int RecoverUnraised(StoreTransaction transaction) => Recover(transaction, null, unraised: true);

    /// <summary>Called after the actual producer has ended unsuccessfully; a still-running task is not proof of failure.</summary>
    internal static bool RecoverFailedProducer(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        StoreIds.Validate(commandId, nameof(commandId));
        return Recover(transaction, commandId.ToArray(), unraised: true) == 1;
    }

    /// <summary>Settles denied, expired or cancelled approvals; pending and approved remain live.</summary>
    internal static int RecoverTerminalApprovals(StoreTransaction transaction) => Recover(transaction, null, unraised: false);

    internal static bool RecoverTerminalApproval(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        StoreIds.Validate(commandId, nameof(commandId));
        return Recover(transaction, commandId.ToArray(), unraised: false) == 1;
    }

    private static int Recover(StoreTransaction transaction, byte[]? selected, bool unraised)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full) throw new InvalidOperationException("Stage recovery requires FULL durability.");
        if (!HasSchema(transaction)) return 0;
        var ids = new List<(byte[] Id, Reason Why)>();
        using (var query = transaction.CreateCommand(unraised ? """
            SELECT r.command_id, 1 FROM file_private_stage_reservation r
            WHERE r.active = 1 AND ($id IS NULL OR r.command_id = $id)
              AND NOT EXISTS (SELECT 1 FROM file_operation_journal j WHERE j.command_id = r.command_id)
              AND NOT EXISTS (SELECT 1 FROM approval a WHERE a.command_id = r.command_id)
            ORDER BY r.created_at LIMIT 64;
            """ : """
            SELECT r.command_id, CASE a.state WHEN 3 THEN 2 WHEN 4 THEN 3 ELSE 4 END
            FROM file_private_stage_reservation r JOIN approval a ON a.command_id = r.command_id
            JOIN file_private_approval_binding b ON b.command_id = r.command_id AND b.approval_id = a.approval_id
            WHERE r.active = 1 AND a.state IN (3, 4, 5) AND ($id IS NULL OR r.command_id = $id)
              AND NOT EXISTS (SELECT 1 FROM file_operation_journal j WHERE j.command_id = r.command_id)
            ORDER BY r.created_at LIMIT 64;
            """))
        {
            query.Parameters.AddWithValue("$id", (object?)selected ?? DBNull.Value);
            using var row = query.ExecuteReader();
            while (row.Read()) ids.Add(((byte[])row.GetValue(0), (Reason)row.GetInt32(1)));
        }

        foreach (var (id, why) in ids)
        {
            using var query = transaction.CreateCommand("""
                SELECT r.kind, r.request_sha256, r.caller, r.correlation_id, r.workspace_id, r.relative_path, r.created_at,
                       d.method, d.payload_digest, d.origin, d.outcome
                FROM file_private_stage_reservation r JOIN command_dedup d ON d.command_id = r.command_id
                WHERE r.command_id = $id AND r.active = 1;
                """);
            query.Parameters.AddWithValue("$id", id);
            using var row = query.ExecuteReader();
            if (!row.Read() || !row.IsDBNull(10))
                throw new InvalidDataException("The unsettled stage has no available command receipt.");
            var kind = (FileOperationKind)row.GetInt32(0);
            var digest = (byte[])row.GetValue(1);
            var caller = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2));
            var correlation = (byte[])row.GetValue(3);
            var workspace = (byte[])row.GetValue(4);
            var path = row.GetString(5);
            var created = row.GetInt64(6);
            var method = kind == FileOperationKind.Write ? "arcforges.node.v1.FileService/WriteFile" :
                kind == FileOperationKind.Edit ? "arcforges.node.v1.FileService/EditFile" :
                throw new InvalidDataException("Unknown staged operation kind.");
            if (id.Length != 16 || digest.Length != 32 || correlation.Length != 16 || workspace.Length != 16 ||
                CenterRouting.Shape(caller) is not null || row.GetString(7) != method ||
                !CryptographicOperations.FixedTimeEquals(digest, (byte[])row.GetValue(8)) || row.GetInt32(9) != (int)Origin.Remote)
                throw new InvalidDataException("The private stage reservation does not match its command.");
            row.Close();
            var completed = Math.Max(created, transaction.NowMicroseconds);
            var error = Error(why, correlation);
            var outcome = Response(kind, error, correlation);
            // The immutable fence, receipt and active-slot release commit together. Older writers see the trigger.
            transaction.Execute("INSERT INTO file_private_stage_terminal (command_id, completed_at, reason) VALUES ($id, $at, $reason);",
                ("$id", id), ("$at", completed), ("$reason", (int)why));
            if (transaction.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id AND active = 1;", ("$id", id)) != 1)
                throw new InvalidOperationException("The stage reservation changed during recovery.");
            CommandDeduplication.Complete(transaction, id, outcome);
            var actor = new ActorRef { Origin = Origin.Remote, CenterCaller = caller, RemoteCommandId = new Id { Value = ByteString.CopyFrom(id) } };
            AuditLog.AppendFileWorkspace(transaction, actor, "file.recovery FileService." +
                (kind == FileOperationKind.Write ? "WriteFile" : "EditFile"), workspace, null, path,
                PermissionDecision.Deny, "refused: " + error.Code, null);
        }
        return ids.Count;
    }

    internal static FileJournalPreparation? Find(StoreReader reader, FileOperationKind kind, ReadOnlySpan<byte> id,
        CenterCaller caller, ReadOnlySpan<byte> raw)
    {
        var record = Read(reader, id);
        if (record is null) return null;
        return record.Kind == kind && CenterRouting.SameFileCaller(record.Caller, caller) &&
            CryptographicOperations.FixedTimeEquals(record.Digest, SHA256.HashData(raw))
            ? FileJournalPreparation.Existing : FileJournalPreparation.Conflict;
    }

    internal static byte[]? Replay(StoreReader reader, FileOperationKind kind, ReadOnlySpan<byte> id,
        CenterCaller caller, ReadOnlySpan<byte> raw) =>
        Find(reader, kind, id, caller, raw) == FileJournalPreparation.Existing ? Read(reader, id)!.Outcome.ToArray() : null;

    internal static FileOperation? Get(StoreReader reader, ReadOnlySpan<byte> id, CenterCaller? caller)
    {
        var record = Read(reader, id);
        if (record is null || caller is not null && !CenterRouting.SameFileCaller(record.Caller, caller)) return null;
        var operation = new FileOperation
        {
            CommandId = new Id { Value = ByteString.CopyFrom(record.Id) },
            Kind = record.Kind,
            State = FileOperationState.Completed,
            RequestSha256 = ByteString.CopyFrom(record.Digest),
            CreatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.Created)),
            UpdatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(record.Completed)),
            Held = false,
            Acknowledged = false,
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(record.Workspace) }, Path = record.Path },
            Error = Error(record.Why, record.Correlation),
        };
        if (!NodeShapes.IsValid(operation)) throw new InvalidDataException("The terminal stage operation is invalid.");
        return operation;
    }

    internal static bool IsTerminal(StoreReader reader, ReadOnlySpan<byte> id) => Read(reader, id) is not null;

    private static Terminal? Read(StoreReader reader, ReadOnlySpan<byte> id)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(id, nameof(id));
        if (!HasSchema(reader)) return null;
        using var query = reader.CreateCommand("""
            SELECT r.command_id, r.kind, r.request_sha256, r.caller, r.correlation_id, r.workspace_id,
                   r.relative_path, r.created_at, t.completed_at, t.reason, d.outcome, d.method, d.payload_digest, d.origin, r.active
            FROM file_private_stage_terminal t
            JOIN file_private_stage_reservation r ON r.command_id = t.command_id
            JOIN command_dedup d ON d.command_id = r.command_id
            WHERE t.command_id = $id;
            """);
        query.Parameters.AddWithValue("$id", id.ToArray());
        using var row = query.ExecuteReader();
        if (!row.Read()) return null;
        var kind = (FileOperationKind)row.GetInt32(1);
        var method = kind == FileOperationKind.Write ? "arcforges.node.v1.FileService/WriteFile" :
            kind == FileOperationKind.Edit ? "arcforges.node.v1.FileService/EditFile" :
            throw new InvalidDataException("Unknown terminal stage kind.");
        var digest = (byte[])row.GetValue(2);
        var caller = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(3));
        var correlation = (byte[])row.GetValue(4);
        var why = (Reason)row.GetInt32(9);
        var outcome = (byte[])row.GetValue(10);
        if (digest.Length != 32 || correlation.Length != 16 || CenterRouting.Shape(caller) is not null ||
            row.GetInt32(14) != 0 || row.GetInt32(13) != (int)Origin.Remote || row.GetString(11) != method ||
            !CryptographicOperations.FixedTimeEquals(digest, (byte[])row.GetValue(12)) ||
            !CryptographicOperations.FixedTimeEquals(outcome, Response(kind, Error(why, correlation), correlation)))
            throw new InvalidDataException("The terminal stage receipt does not match its reservation.");
        return new Terminal((byte[])row.GetValue(0), kind, digest, caller, correlation, (byte[])row.GetValue(5),
            row.GetString(6), row.GetInt64(7), row.GetInt64(8), why, outcome);
    }

    private static bool HasSchema(StoreReader reader) => reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;") is long version && version >= 9;

    private static ArcError Error(Reason reason, byte[] correlation)
    {
        var (category, code, detail) = reason switch
        {
            Reason.ProducerAbandoned => (ErrorCategory.State, "invalid_state", "file_preparation_abandoned"),
            Reason.ApprovalDenied or Reason.ApprovalCancelled => (ErrorCategory.Authorization, "permission_denied", PermissionMatrix.FileWrite),
            Reason.ApprovalExpired => (ErrorCategory.State, "invalid_state", "approval_expired"),
            _ => throw new InvalidDataException("Unknown terminal stage reason."),
        };
        return new ArcError
        {
            Category = category,
            Code = code,
            MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
            Effect = EffectCertainty.DidNotHappen,
            Retry = new RetryAdvice { Mode = RetryMode.Never },
            CorrelationId = new Id { Value = ByteString.CopyFrom(correlation) },
            Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = detail } },
        };
    }

    private static byte[] Response(FileOperationKind kind, ArcError error, byte[] correlation)
    {
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(correlation) } };
        if (kind == FileOperationKind.Write)
        {
            var write = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(write)) throw new InvalidDataException("Invalid terminal write outcome.");
            return write.ToByteArray();
        }
        var edit = new FileServiceEditFileResponse { Meta = meta, Error = error };
        if (!NodeShapes.IsValid(edit)) throw new InvalidDataException("Invalid terminal edit outcome.");
        return edit.ToByteArray();
    }
}
