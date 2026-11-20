// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

internal enum StoredTransferDirection { Import, Export }

internal enum StoredTransferState { Open = 1, Streaming, Complete, Failed, RecoveryRequired }

internal enum StoredTransferCloseReason { ExplicitClose, Expiry }

internal enum StoredTransferPhase { Begin, Chunk, Publish, Close, Expire }

/// <summary>Private native evidence and the receipt that authorized the pending effect.</summary>
internal sealed record StoredTransferPending(StoredTransferPhase Phase, string? CommandId, long? Offset = null,
    long? Length = null, string? Sha256 = null, string? TargetIdentity = null, string? ParentIdentity = null);

internal sealed record StoredTransferManifest(long Revision, string ActorId, long SandboxRevision,
    string RootIdentity, long RootGeneration, string RelativePath, bool Overwrite = false,
    string? ExpectedFileVersion = null, string? GrantId = null, long? GrantRevision = null, string? EnrollmentId = null,
    StoredTransferPending? Pending = null, int FormatVersion = 1, string? SnapshotVersion = null,
    string? TargetParentIdentity = null, string? StageRootIdentity = null);

internal sealed record StoredTransfer(string TransferId, string SandboxId, string OwnerId, byte[] OwnerEpoch,
    string BeginCommandId, StoredTransferDirection Direction, StoredTransferState State, StoredTransferManifest Manifest,
    string StagingIdentity, long ByteLength, long VerifiedOffset, string ExpectedSha256, DateTimeOffset ExpiresAt,
    DateTimeOffset? ClosedAt = null, StoredTransferCloseReason? CloseReason = null, int Effect = 1);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(StoredTransferManifest))]
internal sealed partial class TransferManifestJsonContext : JsonSerializerContext;

/// <summary>Owned single-file transfer records in the existing schema 16 table.</summary>
internal static class TransferRecords
{
    internal const string UnboundStage = "unbound";
    internal const string BeginImportMethod = "DataService.BeginImport";
    internal const string BeginExportMethod = "DataService.BeginExport";
    internal const string WriteMethod = "DataService.WriteImport";
    internal const string CommitMethod = "DataService.CommitImport";
    internal const string CloseMethod = "DataService.CloseTransfer";
    internal const string Aggregate = "transfer";
    private const string Owned = """
        SELECT t.transfer_id,t.sandbox_id,t.owner_id,t.owner_epoch,t.command_id,t.direction,t.state,t.manifest_json,
            t.staging_identity,t.byte_length,t.verified_offset,t.expected_sha256,t.expires_utc,t.closed_utc,t.close_reason,
            t.effect_certainty
        FROM transfer AS t JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
        WHERE t.owner_id=$owner
        """;

    internal static StoredTransfer? Get(StoreReader reader, string ownerId, string id)
    {
        using var command = reader.CreateCommand(Owned + " AND t.transfer_id=$id;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", id)]);
        using var rows = command.ExecuteReader();
        return rows.Read() ? Read(rows) : null;
    }

    internal static bool MatchesRemote(StoredTransfer row, ReadOnlySpan<byte> ownerEpoch, DurableRemoteBinding binding) =>
        row.OwnerEpoch.AsSpan().SequenceEqual(ownerEpoch) && MatchesManifestAuthority(row, binding);

    internal static bool HasBoundBeginReceipt(StoreReader reader, StoredTransfer row, DurableRemoteBinding binding) =>
        ReadPhaseAuthority(reader, row, row.BeginCommandId, PhaseMethod(row.Direction, StoredTransferPhase.Begin))
            == (true, binding);

    internal static IReadOnlyList<StoredTransfer> ListPending(StoreReader reader, string ownerId, int limit, string? after = null) =>
        List(reader, Owned + """
             AND t.closed_utc IS NULL AND json_type(t.manifest_json,'$.pending')='object'
               AND ($after IS NULL OR t.transfer_id>$after)
             ORDER BY t.transfer_id LIMIT $limit;
            """, ownerId, limit, after);

    internal static IReadOnlyList<StoredTransfer> ListExpired(StoreReader reader, string ownerId, DateTimeOffset now, int limit,
        string? after = null) =>
        List(reader, Owned + """
             AND t.closed_utc IS NULL AND t.expires_utc<=$now AND ($after IS NULL OR t.transfer_id>$after)
               AND t.state<>5 AND t.effect_certainty<>3 AND json_extract(t.manifest_json,'$.pending') IS NULL
             ORDER BY t.transfer_id LIMIT $limit;
            """, ownerId, limit, after, now);

    internal static bool HasMutationGate(StoreReader reader, string ownerId, string sandboxId, string? exceptTransferId = null) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM transfer AS t JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
                WHERE t.owner_id=$owner AND t.sandbox_id=$sandbox AND t.transfer_id IS NOT $except
                  AND t.closed_utc IS NULL AND (t.state IN (1,2,5) OR t.effect_certainty=3));
            """, ("$owner", ownerId), ("$sandbox", sandboxId), ("$except", exceptTransferId)), 1L);

    internal static long ReservedBytes(StoreReader reader, string ownerId, string? sandboxId = null) =>
        (long)reader.Scalar("""
            SELECT coalesce(sum(t.byte_length),0) FROM transfer AS t
            JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
            WHERE t.owner_id=$owner AND ($sandbox IS NULL OR t.sandbox_id=$sandbox) AND t.closed_utc IS NULL;
            """, ("$owner", ownerId), ("$sandbox", sandboxId))!;

    /// <summary>Commits the Open row after its exact Begin receipt and before stage creation.</summary>
    internal static void Reserve(StoreTransaction transaction, StoredTransfer row)
    {
        RequireFull(transaction);
        if (!Valid(row) || row is not
            {
                State: StoredTransferState.Open, StagingIdentity: UnboundStage, VerifiedOffset: 0,
                ClosedAt: null, Manifest: { Revision: 1, Pending.Phase: StoredTransferPhase.Begin }
            })
            throw new ArgumentException("A transfer reservation requires its unbound stage and exact Begin journal.", nameof(row));

        if (!HasPhaseAuthority(transaction, row, row.BeginCommandId, PhaseMethod(row.Direction, StoredTransferPhase.Begin)))
            throw new InvalidOperationException("The Begin receipt does not authorize this transfer actor and scope.");

        if (transaction.Execute("""
            INSERT INTO transfer(transfer_id,sandbox_id,owner_id,owner_epoch,command_id,direction,state,manifest_json,
                staging_identity,byte_length,verified_offset,expected_sha256,expires_utc,effect_certainty)
            SELECT $id,$sandbox,$owner,$epoch,$command,$direction,$state,$manifest,$stage,$bytes,0,$sha,$expires,$effect
            FROM sandbox AS s JOIN command_receipt AS r ON r.owner_id=s.owner_id AND r.owner_epoch=$epoch
            WHERE s.owner_id=$owner AND s.sandbox_id=$sandbox AND s.state=$ready AND s.revision=$revision
              AND s.root_identity=$root AND s.root_generation=$generation
              AND r.command_id=$command AND r.method=$method AND r.aggregate_kind='transfer'
              AND r.aggregate_id=$id AND r.state='ACCEPTED';
            """, ("$id", row.TransferId), ("$sandbox", row.SandboxId), ("$owner", row.OwnerId), ("$epoch", row.OwnerEpoch),
            ("$command", row.BeginCommandId), ("$direction", Direction(row.Direction)), ("$state", (int)row.State),
            ("$manifest", Serialize(row.Manifest)), ("$stage", row.StagingIdentity), ("$bytes", row.ByteLength),
            ("$sha", row.ExpectedSha256), ("$expires", Time(row.ExpiresAt)), ("$effect", row.Effect),
            ("$ready", (int)StoredSandboxState.Ready), ("$revision", row.Manifest.SandboxRevision),
            ("$root", row.Manifest.RootIdentity), ("$generation", row.Manifest.RootGeneration),
            ("$method", row.Direction == StoredTransferDirection.Import ? BeginImportMethod : BeginExportMethod)) != 1)
            throw new InvalidOperationException("The exact owned Sandbox and Begin receipt do not authorize this transfer.");
    }

    /// <summary>Compare-and-swap one ownership-locked observation in a FULL transaction.</summary>
    internal static bool Advance(StoreTransaction transaction, StoredTransfer before, StoredTransfer after)
    {
        RequireFull(transaction);
        if (!Valid(before) || !Valid(after) || !CanAdvance(before, after))
            throw new ArgumentException("The observed transfer does not preserve its identity and permitted lifecycle.", nameof(after));

        var witness = after.Manifest.Pending ?? before.Manifest.Pending;
        string? witnessMethod = witness?.CommandId is null ? null : PhaseMethod(before.Direction, witness.Phase);
        if (!HasPhaseAuthority(transaction, before, witness?.CommandId, witnessMethod))
            return false;

        return transaction.Execute("""
            UPDATE transfer SET state=$state,manifest_json=$manifest,staging_identity=$stage,verified_offset=$offset,
                expected_sha256=$sha,closed_utc=$closed,close_reason=$reason,effect_certainty=$effect
            WHERE transfer_id=$id AND sandbox_id=$sandbox AND owner_id=$owner AND owner_epoch=$epoch AND command_id=$command
              AND direction=$direction AND state=$oldState AND manifest_json=$oldManifest AND staging_identity=$oldStage
              AND byte_length=$length AND verified_offset=$oldOffset AND expected_sha256=$oldSha
              AND expires_utc=$expiry AND closed_utc IS NULL AND effect_certainty=$oldEffect
              AND ($witness IS NULL OR EXISTS(SELECT 1 FROM command_receipt
                WHERE owner_id=$owner AND owner_epoch=$epoch AND command_id=$witness AND method=$witnessMethod
                  AND aggregate_kind='transfer' AND aggregate_id=$id AND state IN ('ACCEPTED','UNKNOWN')));
            """, ("$state", (int)after.State), ("$manifest", Serialize(after.Manifest)), ("$stage", after.StagingIdentity),
            ("$offset", after.VerifiedOffset), ("$sha", after.ExpectedSha256), ("$closed", after.ClosedAt is { } at ? Time(at) : null),
            ("$reason", Reason(after.CloseReason)), ("$effect", after.Effect), ("$id", before.TransferId),
            ("$sandbox", before.SandboxId), ("$owner", before.OwnerId), ("$epoch", before.OwnerEpoch), ("$command", before.BeginCommandId),
            ("$direction", Direction(before.Direction)), ("$oldState", (int)before.State), ("$oldManifest", Serialize(before.Manifest)),
            ("$oldStage", before.StagingIdentity), ("$length", before.ByteLength), ("$oldOffset", before.VerifiedOffset),
            ("$oldSha", before.ExpectedSha256), ("$expiry", Time(before.ExpiresAt)), ("$oldEffect", before.Effect),
            ("$witness", witness?.CommandId), ("$witnessMethod", witnessMethod)) == 1;
    }

    internal static bool CanSettleReadyImport(StoreReader reader, string ownerId, byte[] epoch, string commandId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM transfer AS t
                JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
                JOIN command_receipt AS r ON r.owner_id=t.owner_id AND r.owner_epoch=t.owner_epoch AND r.command_id=t.command_id
                WHERE t.owner_id=$owner AND t.owner_epoch=$epoch AND t.command_id=$command
                  AND r.method=$method AND r.aggregate_kind='transfer' AND r.aggregate_id=t.transfer_id
                  AND t.direction='import' AND t.state=$open AND t.effect_certainty=1 AND t.verified_offset=0
                  AND t.closed_utc IS NULL AND t.staging_identity<>$unbound AND length(t.staging_identity)>0
                  AND json_extract(t.manifest_json,'$.pending') IS NULL);
            """, ("$owner", ownerId), ("$epoch", epoch), ("$command", commandId), ("$method", BeginImportMethod),
            ("$open", (int)StoredTransferState.Open), ("$unbound", UnboundStage)), 1L);

    internal static bool IsCloseSafetyParent(StoreReader reader, string ownerId, byte[] epoch, string transferId, string beginCommandId) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(SELECT 1 FROM transfer AS t
                JOIN sandbox AS s ON s.sandbox_id=t.sandbox_id AND s.owner_id=t.owner_id
                JOIN command_receipt AS r ON r.owner_id=t.owner_id AND r.owner_epoch=t.owner_epoch AND r.command_id=t.command_id
                WHERE t.owner_id=$owner AND t.owner_epoch=$epoch AND t.transfer_id=$transfer AND t.command_id=$begin
                  AND r.aggregate_kind='transfer' AND r.aggregate_id=t.transfer_id AND r.safety_parent_command_id IS NULL
                  AND ((t.direction='import' AND r.method=$import) OR (t.direction='export' AND r.method=$export))
                  AND t.closed_utc IS NULL);
            """, ("$owner", ownerId), ("$epoch", epoch), ("$transfer", transferId), ("$begin", beginCommandId),
            ("$import", BeginImportMethod), ("$export", BeginExportMethod)), 1L);

    private static bool MatchesManifestAuthority(StoredTransfer row, DurableRemoteBinding? binding) =>
        binding is null ? row.Manifest.GrantId is null
            : binding.ScopeKind == "sandbox" && binding.SandboxId == row.SandboxId
                && binding.ActorId == row.Manifest.ActorId && binding.GrantId == row.Manifest.GrantId
                && binding.GrantRevision == row.Manifest.GrantRevision && binding.EnrollmentId == row.Manifest.EnrollmentId;

    private static bool HasPhaseAuthority(StoreReader reader, StoredTransfer row, string? commandId, string? method)
    {
        string beginMethod = PhaseMethod(row.Direction, StoredTransferPhase.Begin);
        var begin = ReadPhaseAuthority(reader, row, row.BeginCommandId, beginMethod);
        if (!begin.Found || !MatchesManifestAuthority(row, begin.Binding))
            return false;

        // Expiry has no caller command. Existing accepted phases may still settle proven effects
        // after revocation, but only with the original authority retained in their own receipts.
        return commandId is null || commandId == row.BeginCommandId && method == beginMethod
            || ReadPhaseAuthority(reader, row, commandId, method!) == begin;
    }

    private static (bool Found, DurableRemoteBinding? Binding) ReadPhaseAuthority(StoreReader reader, StoredTransfer row,
        string commandId, string method)
    {
        using var command = reader.CreateCommand("""
            SELECT b.account_id,b.actor_id,b.enrollment_id,b.protocol_epoch,b.grant_id,b.grant_revision,b.scope_kind,b.sandbox_id
            FROM command_receipt AS r LEFT JOIN remote_command_binding AS b USING(owner_id,owner_epoch,command_id)
            WHERE r.owner_id=$owner AND r.owner_epoch=$epoch AND r.command_id=$command AND r.method=$method
              AND r.aggregate_kind='transfer' AND r.aggregate_id=$transfer;
            """);
        StoreReader.Bind(command, [("$owner", row.OwnerId), ("$epoch", row.OwnerEpoch), ("$command", commandId),
            ("$method", method), ("$transfer", row.TransferId)]);
        using var result = command.ExecuteReader();
        if (!result.Read()) return default;
        return (true, result.IsDBNull(0) ? null : new(result.GetString(0), result.GetString(1), result.GetString(2),
            result.GetString(3), result.GetString(4), result.GetInt64(5), result.GetString(6),
            result.IsDBNull(7) ? null : result.GetString(7)));
    }

    private static string PhaseMethod(StoredTransferDirection direction, StoredTransferPhase phase) => phase switch
    {
        StoredTransferPhase.Begin when direction == StoredTransferDirection.Import => BeginImportMethod,
        StoredTransferPhase.Begin => BeginExportMethod,
        StoredTransferPhase.Chunk => WriteMethod,
        StoredTransferPhase.Publish => CommitMethod,
        StoredTransferPhase.Close => CloseMethod,
        _ => throw new InvalidOperationException("The pending transfer phase cannot bind a receipt."),
    };

    private static List<StoredTransfer> List(StoreReader reader, string sql, string ownerId, int limit, string? after,
        DateTimeOffset? now = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);
        using var command = reader.CreateCommand(sql);
        StoreReader.Bind(command, [("$owner", ownerId), ("$limit", limit), ("$after", after)]);
        if (now is { } time) StoreReader.Bind(command, [("$now", Time(time))]);
        using var rows = command.ExecuteReader();
        var result = new List<StoredTransfer>();
        while (rows.Read())
        {
            result.Add(Read(rows));
        }

        return result;
    }

    private static StoredTransfer Read(SqliteDataReader row)
    {
        StoredTransferManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize(row.GetString(7), TransferManifestJsonContext.Default.StoredTransferManifest)
                ?? throw new DurableStoreMaintenanceException();
        }
        catch (JsonException)
        {
            throw new DurableStoreMaintenanceException();
        }
        var result = new StoredTransfer(row.GetString(0), row.GetString(1), row.GetString(2), row.GetFieldValue<byte[]>(3),
            row.GetString(4), row.GetString(5) switch
            {
                "import" => StoredTransferDirection.Import,
                "export" => StoredTransferDirection.Export,
                _ => throw new DurableStoreMaintenanceException(),
            }, (StoredTransferState)row.GetInt32(6), manifest, row.GetString(8), row.GetInt64(9), row.GetInt64(10),
            row.GetString(11), ParseTime(row.GetString(12)), row.IsDBNull(13) ? null : ParseTime(row.GetString(13)),
            row.IsDBNull(14) ? null : row.GetString(14) switch
            {
                "explicit_close" => StoredTransferCloseReason.ExplicitClose,
                "expiry" => StoredTransferCloseReason.Expiry,
                _ => throw new DurableStoreMaintenanceException(),
            }, row.GetInt32(15));
        return Valid(result) ? result : throw new DurableStoreMaintenanceException();
    }

    private static bool CanAdvance(StoredTransfer before, StoredTransfer after)
    {
        var oldManifest = before.Manifest;
        var newManifest = after.Manifest;
        if (before.ClosedAt.HasValue || newManifest.Revision != checked(oldManifest.Revision + 1)
            || newManifest with
            {
                Revision = oldManifest.Revision,
                Pending = oldManifest.Pending,
                SnapshotVersion = oldManifest.SnapshotVersion
            } != oldManifest
            || oldManifest.SnapshotVersion != newManifest.SnapshotVersion && (oldManifest.SnapshotVersion is not null
                || before.Direction != StoredTransferDirection.Export || after.State != StoredTransferState.Complete)
            || before.TransferId != after.TransferId || before.SandboxId != after.SandboxId || before.OwnerId != after.OwnerId
            || !before.OwnerEpoch.AsSpan().SequenceEqual(after.OwnerEpoch) || before.BeginCommandId != after.BeginCommandId
            || before.Direction != after.Direction || before.ByteLength != after.ByteLength || before.ExpiresAt != after.ExpiresAt
            || before.StagingIdentity != after.StagingIdentity && (before.StagingIdentity != UnboundStage
                || oldManifest.Pending?.Phase != StoredTransferPhase.Begin)
            || before.ExpectedSha256 != after.ExpectedSha256 && (before.Direction != StoredTransferDirection.Export
                || before.ExpectedSha256.Length != 0 || after.State != StoredTransferState.Complete)
            || after.VerifiedOffset < before.VerifiedOffset)
            return false;

        bool resolvedPrivateImport = before.State == StoredTransferState.RecoveryRequired
            && before.Direction == StoredTransferDirection.Import && before.StagingIdentity != UnboundStage
            && newManifest.Pending is null && after.Effect == 1 &&
            (oldManifest.Pending is { Phase: StoredTransferPhase.Begin } && after.State == StoredTransferState.Open && after.VerifiedOffset == 0
             || oldManifest.Pending is { Phase: StoredTransferPhase.Chunk }
                 && after.State == (after.VerifiedOffset == 0 ? StoredTransferState.Open : StoredTransferState.Streaming));
        if (!resolvedPrivateImport && before.State != after.State && (before.State, after.State) is not
            ((StoredTransferState.Open, StoredTransferState.Streaming or StoredTransferState.Complete or StoredTransferState.Failed or StoredTransferState.RecoveryRequired)
            or (StoredTransferState.Streaming, StoredTransferState.Complete or StoredTransferState.Failed or StoredTransferState.RecoveryRequired)
            or (StoredTransferState.RecoveryRequired, StoredTransferState.Complete or StoredTransferState.Failed)))
            return false;

        if (oldManifest.Pending is { } pending && newManifest.Pending is { } next
            && (pending.Phase != next.Phase || pending.CommandId != next.CommandId || pending.Offset != next.Offset
                || pending.Length != next.Length || pending.Sha256 != next.Sha256
                || pending.TargetIdentity is not null && next.TargetIdentity != pending.TargetIdentity
                || pending.ParentIdentity is not null && next.ParentIdentity != pending.ParentIdentity))
            return false;

        if (after.VerifiedOffset > before.VerifiedOffset && before.Direction == StoredTransferDirection.Import
            && (oldManifest.Pending is not { Phase: StoredTransferPhase.Chunk, Length: { } count }
                || after.VerifiedOffset - before.VerifiedOffset != count || newManifest.Pending is not null))
            return false;

        if (after.State == StoredTransferState.Complete && before.State != StoredTransferState.Complete
            && oldManifest.Pending?.Phase != (before.Direction == StoredTransferDirection.Import
                ? StoredTransferPhase.Publish : StoredTransferPhase.Begin))
            return false;

        return after.ClosedAt is null || (oldManifest.Pending?.Phase, after.CloseReason) is
            ((StoredTransferPhase.Close, StoredTransferCloseReason.ExplicitClose)
            or (StoredTransferPhase.Expire, StoredTransferCloseReason.Expiry));
    }

    private static bool Valid(StoredTransfer row)
    {
        var manifest = row.Manifest;
        if (!Hex(row.TransferId, 32) || !Hex(row.SandboxId, 32) || !Hex(row.BeginCommandId, 32) || row.OwnerEpoch.Length != StoreIds.Length
            || !Token(row.OwnerId) || !Token(manifest.ActorId) || !Token(manifest.RootIdentity) || !Token(row.StagingIdentity)
            || manifest.Revision < 1 || manifest.SandboxRevision < 1 || manifest.RootGeneration < 1 || manifest.FormatVersion != 1
            || !Token(manifest.RelativePath) || !ValidGrant(row.OwnerId, manifest) || row.ByteLength < 0
            || row.VerifiedOffset < 0 || row.VerifiedOffset > row.ByteLength
            || manifest.ExpectedFileVersion is { } version && !Token(version)
            || (row.Direction == StoredTransferDirection.Import) != (manifest.TargetParentIdentity is not null)
            || manifest.TargetParentIdentity is { } targetParent && !Token(targetParent)
            || !Token(manifest.StageRootIdentity)
            || row.Direction == StoredTransferDirection.Import && manifest.Overwrite != (manifest.ExpectedFileVersion is not null)
            || row.Direction == StoredTransferDirection.Export && manifest.Overwrite
            || row.Direction is not (StoredTransferDirection.Import or StoredTransferDirection.Export)
            || (row.Direction == StoredTransferDirection.Export && row.State == StoredTransferState.Complete
                ? !Token(manifest.SnapshotVersion) : manifest.SnapshotVersion is not null)
            || !Hex(row.ExpectedSha256, 64) && (row.Direction != StoredTransferDirection.Export
                || row.ExpectedSha256.Length != 0 || row.State == StoredTransferState.Complete)
            || (row.ClosedAt is null) != (row.CloseReason is null))
            return false;

        if (row.ClosedAt is not null && (row.State is not (StoredTransferState.Complete or StoredTransferState.Failed)
            || manifest.Pending is not null || row.CloseReason is not (StoredTransferCloseReason.ExplicitClose or StoredTransferCloseReason.Expiry)))
            return false;

        bool stateValid = row.State switch
        {
            StoredTransferState.Open or StoredTransferState.Streaming => row.Effect == 1 && row.ClosedAt is null,
            StoredTransferState.Complete => row.Effect == 2 && row.VerifiedOffset == row.ByteLength && row.StagingIdentity != UnboundStage,
            StoredTransferState.Failed => row.Effect == 1,
            StoredTransferState.RecoveryRequired => row.Effect == 3 && manifest.Pending is not null,
            _ => false,
        };
        return stateValid && (row.StagingIdentity != UnboundStage || row.VerifiedOffset == 0
            && (manifest.Pending?.Phase == StoredTransferPhase.Begin || row.State == StoredTransferState.Failed))
            && ValidPending(row);
    }

    private static bool ValidGrant(string ownerId, StoredTransferManifest manifest) => manifest.GrantId is null
        ? manifest.GrantRevision is null && manifest.EnrollmentId is null && manifest.ActorId == ownerId
        : RemoteId(manifest.GrantId) && manifest.GrantRevision > 0 && RemoteId(manifest.EnrollmentId) && RemoteId(manifest.ActorId);

    private static bool RemoteId(string? value) => Hex(value, 32) && value.AsSpan().ContainsAnyExcept('0');

    private static bool ValidPending(StoredTransfer row)
    {
        var pending = row.Manifest.Pending;
        if (pending is null) return true;
        if (pending.TargetIdentity is { } target && !Token(target) || pending.ParentIdentity is { } parent && !Token(parent))
            return false;
        if (pending.Phase == StoredTransferPhase.Expire ? pending.CommandId is not null
            : pending.CommandId is null || !Hex(pending.CommandId, 32))
            return false;
        if (pending.Phase == StoredTransferPhase.Chunk)
            return row.Direction == StoredTransferDirection.Import && row.State is not (StoredTransferState.Complete or StoredTransferState.Failed)
                && pending.Offset == row.VerifiedOffset && pending.Length is > 0 and <= 1_048_576
                && pending.Length <= row.ByteLength - row.VerifiedOffset && pending.Sha256 is { } sha && Hex(sha, 64);
        if (pending.Offset is not null || pending.Length is not null || pending.Sha256 is not null)
            return false;
        return pending.Phase switch
        {
            StoredTransferPhase.Begin => pending.CommandId == row.BeginCommandId
                && row.State is StoredTransferState.Open or StoredTransferState.Streaming or StoredTransferState.RecoveryRequired,
            StoredTransferPhase.Publish => row.Direction == StoredTransferDirection.Import && row.VerifiedOffset == row.ByteLength
                && row.State is StoredTransferState.Open or StoredTransferState.Streaming or StoredTransferState.RecoveryRequired,
            StoredTransferPhase.Close or StoredTransferPhase.Expire => row.ClosedAt is null,
            _ => false,
        };
    }

    private static bool Hex(string? value, int length) => value?.Length == length && value.All(char.IsAsciiHexDigitLower);

    private static bool Token(string? value) => value is { Length: > 0 and <= 4096 } && !value.Any(char.IsControl);

    private static string Direction(StoredTransferDirection value) => value == StoredTransferDirection.Import ? "import" : "export";

    private static string? Reason(StoredTransferCloseReason? value) => value switch
    {
        StoredTransferCloseReason.ExplicitClose => "explicit_close",
        StoredTransferCloseReason.Expiry => "expiry",
        _ => null,
    };

    private static string Serialize(StoredTransferManifest manifest) =>
        JsonSerializer.Serialize(manifest, TransferManifestJsonContext.Default.StoredTransferManifest);

    private static string Time(DateTimeOffset value) => SandboxRecords.FormatTime(value);

    private static DateTimeOffset ParseTime(string value) => DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static void RequireFull(StoreTransaction transaction)
    {
        if (transaction.Durability != CommitDurability.Full)
            throw new InvalidOperationException("Transfer evidence requires a FULL writer transaction.");
    }
}
