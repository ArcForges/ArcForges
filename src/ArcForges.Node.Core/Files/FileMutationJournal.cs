// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Metadata obtained by the future native effect implementation after it has verified the held root, parent and target
/// and flushed private anonymous stages on the same volume. Constructing this record does not perform those checks.
/// Nothing in this component grants authority, writes a file, or opens a public method.
/// </summary>
internal sealed record FileJournalIntent(
    FileOperationKind Kind,
    byte[] CommandId,
    byte[] CorrelationId,
    CenterCaller Caller,
    byte[] WorkspaceId,
    string RelativePath,
    int IdentityPlatform,
    byte[] RootIdentity,
    byte[] ParentIdentity,
    byte[]? TargetIdentity,
    long? OriginalSize,
    byte[]? OriginalSha256,
    byte[]? OriginalStageIdentity,
    long IntendedSize,
    byte[] IntendedSha256,
    byte[] IntendedStageIdentity);

internal enum FileJournalPreparation
{
    Prepared,
    Existing,
    Conflict,
    WorkspaceHeld,
    Capacity,
}

internal enum FileJournalAcknowledgment
{
    Acknowledged,
    NotFound,
    DigestMismatch,
    InvalidState,
    WorkerNotEnded,
}

/// <summary>
/// Transactional, content-free part of the 06a section 6 journal. This internal component is not yet connected to a
/// filesystem effect or an IPC endpoint. Its caller must prove the native identities, private stage, flush, authorization,
/// deadline and before-effect checks. Recovery only makes an uncertainty durable; it does not inspect or modify user files.
/// </summary>
internal static partial class FileMutationJournal
{
    private const int MaximumRequestBytes = 245_760;
    private const int MaximumFileBytes = 4 * 1024 * 1024;
    private const long MaximumStageBytes = 256L * 1024 * 1024;
    private const int MaximumActive = 64;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Reserves a command and records its checked metadata together in one FULL transaction. The digest covers the exact
    /// received request bytes, including RequestMeta, not a reserialized message or the legacy PayloadDigest.
    /// </summary>
    internal static FileJournalPreparation Prepare(StoreTransaction transaction, FileJournalIntent intent, ReadOnlySpan<byte> transmitted,
        WorkspacePath? selectedRoot = null)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(intent);
        var found = FindExisting(transaction, intent.Kind, intent.CommandId, intent.Caller, transmitted);
        if (found is not null) return found.Value;
        ValidateIntent(intent, transmitted);
        var digest = SHA256.HashData(transmitted);
        var caller = Sanitize(intent.Caller);

        // A live receipt without a corresponding journal is not an effect this component can adopt.
        if (transaction.Scalar("""
            SELECT 1 FROM command_dedup WHERE command_id = $id AND
              (expires_at > $now OR EXISTS (SELECT 1 FROM routed_file_command_retention WHERE command_id = $id));
            """, ("$id", intent.CommandId), ("$now", transaction.NowMicroseconds)) is not null)
            return FileJournalPreparation.Conflict;

        var distinctHeldIds = new List<byte[]>();
        if (HasTargetHold(transaction, intent.IdentityPlatform, intent.ParentIdentity, intent.TargetIdentity, intent.RelativePath, selectedRoot, distinctHeldIds))
        {
            return FileJournalPreparation.WorkspaceHeld;
        }

        // Persistent named reservations and held journals use one command-aware stage ledger. The native stage
        // lease is also charged in the node runtime until the actual handles close.
        var capacity = FileStageCapacity.Durable(transaction);
        var newBytes = checked((intent.OriginalSize ?? 0) + intent.IntendedSize);
        if (capacity.Active >= MaximumActive || newBytes > MaximumStageBytes - capacity.Bytes)
            return FileJournalPreparation.Capacity;

        var method = intent.Kind == FileOperationKind.Write
            ? "arcforges.node.v1.FileService/WriteFile" : "arcforges.node.v1.FileService/EditFile";
        var decision = CommandDeduplication.Begin(transaction, intent.CommandId, method, digest, Origin.Remote);
        if (decision.Status != DedupStatus.Execute)
        {
            // A pre-existing receipt without this journal cannot be adopted as evidence of a file effect.
            return FileJournalPreparation.Conflict;
        }

        var now = transaction.NowMicroseconds;
        var absent = intent.TargetIdentity is null;
        try
        {
            foreach (var heldId in distinctHeldIds)
                transaction.AllowDistinctFileTarget(intent.CommandId, heldId, intent.WorkspaceId, intent.RelativePath,
                    intent.RootIdentity, intent.ParentIdentity, intent.TargetIdentity!, digest, caller.ToByteArray(), (long)intent.Kind);
            transaction.Execute("""
            INSERT INTO file_operation_journal
              (command_id, kind, phase, request_sha256, caller, correlation_id, workspace_id, relative_path,
               identity_platform, root_identity, parent_identity, target_identity, expected_absent,
               original_size, original_sha256, original_stage_identity, intended_size, intended_sha256,
               intended_stage_identity, created_at, updated_at, held, acknowledged)
            VALUES ($id, $kind, 1, $digest, $caller, $correlation, $workspace, $path,
                    $platform, $root, $parent, $target, $absent, $original_size, $original_hash, $original_stage,
                    $intended_size, $intended_hash, $intended_stage, $now, $now, 1, 0);
            """,
            ("$id", intent.CommandId), ("$kind", (int)intent.Kind), ("$digest", digest),
            ("$caller", caller.ToByteArray()), ("$correlation", intent.CorrelationId),
            ("$workspace", intent.WorkspaceId), ("$path", intent.RelativePath), ("$platform", intent.IdentityPlatform),
            ("$root", intent.RootIdentity), ("$parent", intent.ParentIdentity), ("$target", intent.TargetIdentity),
            ("$absent", absent ? 1 : 0), ("$original_size", intent.OriginalSize), ("$original_hash", intent.OriginalSha256),
            ("$original_stage", intent.OriginalStageIdentity), ("$intended_size", intent.IntendedSize),
            ("$intended_hash", intent.IntendedSha256), ("$intended_stage", intent.IntendedStageIdentity), ("$now", now));
        }
        finally
        {
            transaction.ClearFileTargetWitnesses();
        }
        return FileJournalPreparation.Prepared;
    }

    /// <summary>
    /// Looks up a replay before opening the target or creating a stage. The caller must already have matched the signed
    /// command ID and raw request. Null means no journal; a mismatch is a conflict, never a new execution.
    /// </summary>
    internal static FileJournalPreparation? FindExisting(StoreReader reader, FileOperationKind kind, ReadOnlySpan<byte> commandId,
        CenterCaller caller, ReadOnlySpan<byte> transmitted)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(caller);
        StoreIds.Validate(commandId, nameof(commandId));
        if (commandId.IndexOfAnyExcept((byte)0) < 0 || kind is not (FileOperationKind.Write or FileOperationKind.Edit) ||
            CenterRouting.Shape(caller) is not null || transmitted.Length is < 1 or > MaximumRequestBytes)
            throw new ArgumentException("A valid verified command, caller and bounded request are required.");
        var existing = ReadRow(reader, commandId);
        if (existing is null) return PrivateStageTerminal.Find(reader, kind, commandId, caller, transmitted);
        return existing.Kind == kind && CryptographicOperations.FixedTimeEquals(existing.RequestSha256, SHA256.HashData(transmitted)) &&
            CenterRouting.SameFileCaller(existing.Caller, caller) ? FileJournalPreparation.Existing : FileJournalPreparation.Conflict;
    }

    /// <summary>
    /// Called only during exclusive node startup before file effects can run. Every unresolved PREPARED entry becomes
    /// UNKNOWN; an anonymous stage's handle may have disappeared and is not represented as available.
    /// </summary>
    internal static int RecoverInterrupted(StoreTransaction transaction)
    {
        RequireFull(transaction);
        var ids = new List<byte[]>();
        using (var select = transaction.CreateCommand("SELECT command_id FROM file_operation_journal WHERE phase = 1;"))
        using (var rows = select.ExecuteReader())
        {
            while (rows.Read()) ids.Add((byte[])rows.GetValue(0));
        }

        foreach (var id in ids)
        {
            _ = MarkUnknown(transaction, id);
        }
        return ids.Count;
    }

    /// <summary>Returns no operation to an unrelated caller; local HUMAN inspection is separately authorized by its endpoint.</summary>
    internal static FileOperation? GetForCaller(StoreReader reader, ReadOnlySpan<byte> commandId, CenterCaller caller)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(commandId, nameof(commandId));
        ArgumentNullException.ThrowIfNull(caller);
        var row = ReadRow(reader, commandId);
        return row is null ? PrivateStageTerminal.Get(reader, commandId, caller) :
            CenterRouting.SameFileCaller(row.Caller, caller) ? ToOperation(row) : null;
    }

    /// <summary>Reads local metadata only; application code must independently establish local HUMAN authority.</summary>
    internal static FileOperation? GetForVerifiedHuman(StoreReader reader, ReadOnlySpan<byte> commandId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(commandId, nameof(commandId));
        var row = ReadRow(reader, commandId);
        return row is null ? PrivateStageTerminal.Get(reader, commandId, caller: null) : ToOperation(row);
    }

    /// <summary>
    /// Releases an UNKNOWN hold after an independently verified local HUMAN decision. It never touches a stage or user
    /// file and does not convert the original uncertain effect into success. The endpoint and interactive check are separate.
    /// </summary>
    internal static FileJournalAcknowledgment AcknowledgeFromVerifiedHuman(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> requestSha256, ActorRef verifiedHuman)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(verifiedHuman);
        if (verifiedHuman.Origin != Origin.Human || verifiedHuman.CenterCaller is not null)
            throw new ArgumentException("The decision must be independently authenticated as a local HUMAN.", nameof(verifiedHuman));
        var actor = new ActorRef { Origin = Origin.Human, ClientKind = verifiedHuman.ClientKind };
        StoreIds.Validate(commandId, nameof(commandId));
        if (requestSha256.Length != 32) throw new ArgumentException("A request SHA-256 has 32 bytes.", nameof(requestSha256));
        var row = ReadRow(transaction, commandId);
        void Audit(PermissionDecision decision, string outcome) => AuditLog.AppendFileWorkspace(transaction, actor,
            "file.acknowledge FileService.AcknowledgeFileOperation", row?.WorkspaceId, null, row?.Path, decision, outcome, null);
        if (row is null)
        {
            Audit(PermissionDecision.Deny, "refused: not_found");
            return FileJournalAcknowledgment.NotFound;
        }
        if (!CryptographicOperations.FixedTimeEquals(row.RequestSha256, requestSha256))
        {
            Audit(PermissionDecision.Deny, "refused: digest_mismatch");
            return FileJournalAcknowledgment.DigestMismatch;
        }
        if (row.State != FileOperationState.Unknown || !row.Held)
        {
            Audit(PermissionDecision.Deny, "refused: invalid_state");
            return FileJournalAcknowledgment.InvalidState;
        }

        if (!FileEffectWorker.MarkEndedIfObserved(transaction, commandId))
        {
            Audit(PermissionDecision.Deny, "refused: file_worker_not_ended");
            return FileJournalAcknowledgment.WorkerNotEnded;
        }

        if (transaction.Execute("""
            UPDATE file_operation_journal SET held = 0, acknowledged = 1, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 3 AND held = 1 AND acknowledged = 0;
            """, ("$id", commandId.ToArray()), ("$now", transaction.NowMicroseconds)) != 1)
            throw new InvalidOperationException("The file journal hold changed during acknowledgment.");
        // Retain the named stage and its identity, but an explicit HUMAN acknowledgment releases its workspace hold.
        // The active slot is released, but retained bytes and object-identity protection remain until safe disposition.
        if (PrivateStageRegistry.HasSchema(transaction))
            transaction.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id AND active = 1;",
                ("$id", commandId.ToArray()));
        Audit(PermissionDecision.Allow, "acknowledged: file_outcome_unknown");
        return FileJournalAcknowledgment.Acknowledged;
    }

    internal static bool HasWorkspaceHold(StoreReader reader, ReadOnlySpan<byte> workspaceId) =>
        reader.Scalar("SELECT 1 FROM file_operation_journal WHERE workspace_id = $id AND held = 1 LIMIT 1;",
            ("$id", workspaceId.ToArray())) is not null;

    private static void RequireFull(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("The file journal requires synchronous=FULL.");
    }

    internal static void ValidateIntent(FileJournalIntent intent, ReadOnlySpan<byte> transmitted)
    {
        StoreIds.Validate(intent.CommandId, nameof(intent.CommandId));
        StoreIds.Validate(intent.CorrelationId, nameof(intent.CorrelationId));
        StoreIds.Validate(intent.WorkspaceId, nameof(intent.WorkspaceId));
        if (intent.CommandId.AsSpan().IndexOfAnyExcept((byte)0) < 0 || intent.CorrelationId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            intent.WorkspaceId.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Journal identifiers must not be zero.", nameof(intent));
        if (CenterRouting.Shape(intent.Caller) is not null || intent.Kind is not (FileOperationKind.Write or FileOperationKind.Edit))
            throw new ArgumentException("A supported verified caller and file mutation are required.", nameof(intent));
        if (transmitted.Length is < 1 or > MaximumRequestBytes || StrictUtf8.GetByteCount(intent.RelativePath) > 4096)
            throw new ArgumentException("The transmitted request or target path is out of bounds.", nameof(transmitted));
        _ = WorkspacePath.Components(intent.RelativePath);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(intent.IdentityPlatform, intent.RootIdentity);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(intent.IdentityPlatform, intent.ParentIdentity);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(intent.IdentityPlatform, intent.IntendedStageIdentity);
        if (intent.TargetIdentity is null)
        {
            if (intent.Kind != FileOperationKind.Write || intent.OriginalSize is not null || intent.OriginalSha256 is not null ||
                intent.OriginalStageIdentity is not null)
                throw new ArgumentException("An absent target cannot have a preimage.", nameof(intent));
        }
        else
        {
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(intent.IdentityPlatform, intent.TargetIdentity);
            if (intent.OriginalSize is not (>= 0 and <= MaximumFileBytes) || intent.OriginalSha256 is not { Length: 32 } ||
                intent.OriginalStageIdentity is null)
                throw new ArgumentException("A checked existing target needs its bounded preimage metadata.", nameof(intent));
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(intent.IdentityPlatform, intent.OriginalStageIdentity);
        }

        if (intent.IntendedSize is < 0 or > MaximumFileBytes || intent.IntendedSha256.Length != 32)
            throw new ArgumentException("The intended staged object is out of bounds.", nameof(intent));

        // Decode only in memory to bind the stored metadata to the actual request; no request or unknown proto fields are stored.
        if (intent.Kind == FileOperationKind.Write)
        {
            var request = FileServiceWriteFileRequest.Parser.ParseFrom(transmitted.ToArray());
            if (!NodeShapes.IsValid(request) || !Matches(request.Meta, request.Path, intent) || !request.HasData ||
                request.Data.Length > 196_608 || request.Data.Length != intent.IntendedSize ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(request.Data.Span), intent.IntendedSha256) ||
                (intent.TargetIdentity is null
                    ? !request.HasExpectedAbsent || !request.ExpectedAbsent
                    : !request.HasExpectedSha256 || !CryptographicOperations.FixedTimeEquals(request.ExpectedSha256.Span, intent.OriginalSha256!)))
                throw new ArgumentException("The write does not match the checked metadata.", nameof(transmitted));
        }
        else
        {
            var request = FileServiceEditFileRequest.Parser.ParseFrom(transmitted.ToArray());
            if (!NodeShapes.IsValid(request) || !Matches(request.Meta, request.Path, intent) ||
                !request.HasExpectedSha256 || !CryptographicOperations.FixedTimeEquals(request.ExpectedSha256.Span, intent.OriginalSha256!))
                throw new ArgumentException("The edit does not match the checked metadata.", nameof(transmitted));
        }
    }

    private static bool Matches(RequestMeta? meta, FilePath? path, FileJournalIntent intent) =>
        meta?.CommandId?.Value.Span.SequenceEqual(intent.CommandId) == true &&
        (meta.CorrelationId is null || meta.CorrelationId.Value.Span.SequenceEqual(intent.CorrelationId)) &&
        path?.WorkspaceId?.Value.Span.SequenceEqual(intent.WorkspaceId) == true &&
        path.HasPath && string.Equals(path.Path, intent.RelativePath, StringComparison.Ordinal);

    internal static CenterCaller Sanitize(CenterCaller caller)
    {
        static Id? Copy(Id? id) => id is null ? null : new Id { Value = ByteString.CopyFrom(id.Value.Span) };
        var result = new CenterCaller { Kind = caller.Kind, AccountId = Copy(caller.AccountId) };
        if (caller.Kind == CenterCallerKind.AccountSession)
        {
            result.UserId = Copy(caller.UserId);
            result.SessionId = Copy(caller.SessionId);
        }
        else
        {
            result.RelayingNodeId = Copy(caller.RelayingNodeId);
            result.LocalOrigin = caller.LocalOrigin;
            result.LocalSessionId = Copy(caller.LocalSessionId);
        }
        return result;
    }

    private sealed record JournalRow(byte[] CommandId, FileOperationKind Kind, FileOperationState State, byte[] RequestSha256,
        CenterCaller Caller, byte[] Correlation, byte[] WorkspaceId, string Path, long Created, long Updated, bool Held, bool Acknowledged,
        long IntendedSize, byte[] IntendedSha256, byte[]? Outcome, bool ExpectedAbsent);

    private static JournalRow? ReadRow(StoreReader reader, ReadOnlySpan<byte> commandId)
    {
        using var command = reader.CreateCommand("""
            SELECT j.command_id, j.kind, j.phase, j.request_sha256, j.caller, j.correlation_id, j.workspace_id, j.relative_path,
                   j.created_at, j.updated_at, j.held, j.acknowledged, j.intended_size, j.intended_sha256, d.outcome, j.expected_absent
            FROM file_operation_journal j JOIN command_dedup d ON d.command_id = j.command_id
            WHERE j.command_id = $id;
            """);
        command.Parameters.AddWithValue("$id", commandId.ToArray());
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        // This component only creates write/edit rows. Removal remains separately implemented.
        if (row.IsDBNull(6) || row.IsDBNull(7) || row.IsDBNull(12) || row.IsDBNull(13) ||
            row.GetInt32(1) is not (1 or 2) || row.GetInt32(2) is not (1 or 2 or 3))
            throw new InvalidDataException("Unsupported file journal record.");
        var caller = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(4));
        if (CenterRouting.Shape(caller) is not null)
            throw new InvalidDataException("Invalid file journal caller.");
        return new JournalRow((byte[])row.GetValue(0), (FileOperationKind)row.GetInt32(1), (FileOperationState)row.GetInt32(2),
            (byte[])row.GetValue(3), caller, (byte[])row.GetValue(5), (byte[])row.GetValue(6), row.GetString(7),
            row.GetInt64(8), row.GetInt64(9), row.GetInt32(10) != 0, row.GetInt32(11) != 0,
            row.GetInt64(12), (byte[])row.GetValue(13), row.IsDBNull(14) ? null : (byte[])row.GetValue(14), row.GetInt32(15) != 0);
    }

    private static FileOperation ToOperation(JournalRow row)
    {
        var operation = new FileOperation
        {
            CommandId = new Id { Value = ByteString.CopyFrom(row.CommandId) },
            Kind = row.Kind,
            State = row.State,
            RequestSha256 = ByteString.CopyFrom(row.RequestSha256),
            CreatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.Created)),
            UpdatedAt = ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.Updated)),
            Held = row.Held,
            Acknowledged = row.Acknowledged,
            WorkspacePath = new FilePath
            {
                WorkspaceId = new Id { Value = ByteString.CopyFrom(row.WorkspaceId) },
                Path = row.Path,
            },
        };
        if (row.State == FileOperationState.Unknown)
        {
            EnsureUnknownOutcome(row);
            operation.Error = UnknownError(row);
        }
        else if (row.State == FileOperationState.Completed)
        {
            var (mutation, error) = CompletedResult(row);
            if (error is not null) operation.Error = error;
            else operation.Mutation = mutation!;
        }
        return operation;
    }
}
